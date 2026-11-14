package PVE::API2::SLLCustoms;

use strict;
use warnings;
use Compress::Zlib qw(crc32);
use B ();
use Digest::SHA qw(sha256_hex);
use Fcntl qw(:flock O_RDONLY O_WRONLY O_CREAT O_NOFOLLOW);
use File::Basename qw(dirname basename);
use File::Path qw(make_path remove_tree);
use File::Temp qw(tempfile tempdir);
use IO::Handle;
use JSON::PP;
use MIME::Base64 qw(decode_base64 encode_base64);
use POSIX qw(strftime);
use Time::HiRes qw(time);
use URI;
use PVE::Exception qw(raise);
use PVE::JSONSchema;
use PVE::RESTHandler;
use PVE::RPCEnvironment;
use PVE::Tools;
use base qw(PVE::RESTHandler);

# These are fixed server-side paths. No request can supply a filesystem path.
my $CONFIG = '/etc/sll-proxmox-makeover/config.json';
my $ASSET_ROOT = '/usr/local/share/sls-proxmox-branding/assets';
my $HELPER = '/usr/local/sbin/sls-proxmox-branding';
my $LOCK = '/var/lib/proxmox-makeover/control.lock';
my $MAINTENANCE = '/var/lib/proxmox-makeover/maintenance.json';
my $STATE = '/var/lib/sll-proxmox-makeover';
my $AUDIT = "$STATE/audit.jsonl";
my $UPLOAD_TTL = 3600;
my $UPLOAD_CHUNK = 192 * 1024;
my $UPLOAD_MAX = 3 * 1024 * 1024;
my $JSON = JSON::PP->new->utf8->canonical->allow_nonref(0)->max_depth(20);
my $DEFAULT = {
    schema_version => 2, update_safe => JSON::PP::true,
    company_name => 'Southland Labs', project_name => 'Proxmox Makeover',
    product_label => 'Proxmox VE',
    page_title => 'Infrastructure - Southland Labs | Proxmox VE',
    login_eyebrow => 'Infrastructure console', login_heading => 'Welcome back.',
    login_subtitle => 'Sign in to manage your infrastructure.',
    footer_text => 'Southland Labs', website_url => 'https://southlandlabs.dev/',
    show_storage_panel => JSON::PP::true,
    fonts => { login => 'default', dashboard => 'default' },
    colors => {
        background => '#141716', surface => '#1b201e', raised => '#242b26',
        border => '#343c36', accent => '#d5b98c', secondary => '#bac8ad',
        text => '#eeede6', muted => '#a5ada7',
    },
};
my @TEXT_KEYS = qw(company_name project_name product_label page_title login_eyebrow login_heading login_subtitle footer_text);
my %TEXT_MAX = (company_name => 80, project_name => 80, product_label => 80,
    page_title => 160, login_eyebrow => 100, login_heading => 100,
    login_subtitle => 240, footer_text => 120);
my @COLOR_KEYS = qw(background surface raised border accent secondary text muted);
my %FONT_PRESETS = map { $_ => 1 } qw(default system dm-sans oxanium serif monospace);

sub clone_default { return $JSON->decode($JSON->encode($DEFAULT)); }
sub require_interactive_user {
    my $user = PVE::RPCEnvironment::get()->get_user() // '';
    die "interactive Proxmox login required\n" if !$user || $user =~ /!/;
    return $user;
}
sub validate_text {
    my ($key, $value) = @_;
    die "missing $key\n" if !defined($value) || ref($value);
    die "$key is empty\n" if $value eq '';
    die "$key is too long\n" if length($value) > $TEXT_MAX{$key};
    die "$key contains control characters\n" if $value =~ /[\x00-\x1f\x7f]/;
    return "$value";
}
sub validate_url {
    my ($value) = @_;
    die "missing website_url\n" if !defined($value) || ref($value) || length($value) > 512;
    die "website_url contains whitespace or control characters\n" if $value =~ /[\s\x00-\x1f\x7f\\]/;
    my $uri = URI->new($value);
    die "website_url must be an HTTPS URL\n" if lc($uri->scheme // '') ne 'https';
    die "website_url must include a hostname\n" if !defined($uri->host) || $uri->host !~ /\A[a-z0-9.-]+\z/i;
    die "website_url must not include user information\n" if defined($uri->userinfo);
    my $port = $uri->port;
    die "website_url has an invalid port\n" if !defined($port) || "$port" !~ /\A[0-9]+\z/ || $port < 1 || $port > 65535;
    $uri->scheme('https');
    return $uri->as_string;
}
sub validate_boolean {
    my ($key, $value) = @_;
    die "$key must be true or false\n" if !defined($value) || ref($value) ne 'JSON::PP::Boolean';
    return $value ? JSON::PP::true : JSON::PP::false;
}
sub validate_config {
    my ($candidate, $stored) = @_;
    die "configuration must be an object\n" if ref($candidate) ne 'HASH';
    my %allowed = map { $_ => 1 } ('schema_version', @TEXT_KEYS, 'website_url', 'show_storage_panel', 'update_safe', 'colors', 'fonts');
    die "unknown configuration field '$_'\n" for grep { !$allowed{$_} } keys %$candidate;
    my $schema = $candidate->{schema_version};
    die "unsupported schema_version\n" if !defined($schema) || ref($schema)
        || !(B::svref_2object(\$schema)->FLAGS & B::SVp_IOK())
        || ($schema != 1 && $schema != 2) || (!$stored && $schema != 2);
    die "schema 1 cannot contain update_safe\n" if $schema == 1 && exists($candidate->{update_safe});
    die "schema 1 cannot contain fonts\n" if $schema == 1 && exists($candidate->{fonts});
    my $clean = clone_default();
    $clean->{$_} = validate_text($_, $candidate->{$_}) for @TEXT_KEYS;
    $clean->{website_url} = validate_url($candidate->{website_url});
    $clean->{show_storage_panel} = validate_boolean('show_storage_panel', $candidate->{show_storage_panel});
    $clean->{update_safe} = $schema == 1 ? JSON::PP::true : validate_boolean('update_safe', $candidate->{update_safe});
    if (exists($candidate->{fonts})) {
        die "fonts must contain login and dashboard\n" if ref($candidate->{fonts}) ne 'HASH'
            || keys(%{$candidate->{fonts}}) != 2;
        for my $key (qw(login dashboard)) {
            my $value = $candidate->{fonts}->{$key};
            die "invalid font '$key'\n" if !defined($value) || ref($value) || !$FONT_PRESETS{$value};
            $clean->{fonts}->{$key} = $value;
        }
    }
    die "colors must be an object\n" if ref($candidate->{colors}) ne 'HASH';
    my %allowed_color = map { $_ => 1 } @COLOR_KEYS;
    die "unknown color field '$_'\n" for grep { !$allowed_color{$_} } keys %{$candidate->{colors}};
    for my $key (@COLOR_KEYS) {
        my $value = $candidate->{colors}->{$key};
        die "invalid color '$key'\n" if !defined($value) || ref($value) || $value !~ /\A#[0-9a-fA-F]{6}\z/;
        $clean->{colors}->{$key} = lc($value);
    }
    return $clean;
}
sub untaint_managed_path {
    my ($path) = @_;
    die "unsafe managed path\n" if !defined($path) || $path =~ m{(?:\A|/)\.\.(?:/|\z)}
        || $path !~ m{\A(/[A-Za-z0-9_./-]+)\z};
    return $1;
}
sub assert_no_symlink {
    my ($path) = @_;
    $path = untaint_managed_path($path);
    my $current = '';
    for my $part (grep { length($_) } split(m{/+}, $path)) {
        $current .= "/$part";
        die "refusing symlink in managed path\n" if -l $current;
    }
    return 1;
}
sub ensure_directory {
    my ($path, $mode, $allow_sticky) = @_;
    assert_no_symlink($path);
    make_path($path, { mode => $mode }) if !-d $path;
    my @st = stat($path);
    die "unsafe managed directory $path\n" if !@st || !-d _ || $st[4] != 0
        || (($st[2] & 0022) && !($allow_sticky && ($st[2] & 01000)));
}
sub ensure_state {
    ensure_directory($STATE, 0700);
    chmod(0700, $STATE) or die "chmod state directory failed: $!\n";
}
sub sync_directory {
    my ($dir) = @_;
    assert_no_symlink($dir);
    sysopen(my $fh, $dir, O_RDONLY | O_NOFOLLOW) or die "open directory $dir failed: $!\n";
    $fh->sync() or die "sync directory $dir failed: $!\n";
    close($fh) or die "close directory $dir failed: $!\n";
}
sub atomic_write {
    my ($path, $data, $mode) = @_;
    $path = untaint_managed_path($path);
    assert_no_symlink($path);
    my $dir = dirname($path);
    ensure_directory($dir, 0700);
    my ($fh, $temporary) = tempfile('.sll-makeover-XXXXXX', DIR => $dir, UNLINK => 0);
    eval {
        binmode($fh);
        chmod($mode, $temporary) or die "chmod temporary file failed: $!\n";
        print {$fh} $data or die "write temporary file failed: $!\n";
        $fh->flush() or die "flush temporary file failed: $!\n";
        $fh->sync() or die "sync temporary file failed: $!\n";
        close($fh) or die "close temporary file failed: $!\n";
        rename($temporary, $path) or die "rename to $path failed: $!\n";
        sync_directory($dir);
        1;
    } or do {
        my $error = $@ || 'unknown atomic write error';
        close($fh) if defined(fileno($fh));
        unlink($temporary) if -e $temporary;
        die $error;
    };
}
sub read_fixed {
    my ($path, $limit) = @_;
    assert_no_symlink($path);
    sysopen(my $fh, $path, O_RDONLY | O_NOFOLLOW) or die "open $path failed: $!\n";
    die "managed file is not regular\n" if !-f $fh;
    binmode($fh);
    my $data = '';
    while (1) {
        my $read = read($fh, my $chunk, 65536);
        die "read $path failed: $!\n" if !defined($read);
        last if !$read;
        $data .= $chunk;
        die "managed file exceeds size limit\n" if length($data) > $limit;
    }
    close($fh) or die "close $path failed: $!\n";
    return $data;
}
sub read_config {
    assert_no_symlink($CONFIG);
    return clone_default() if !-e $CONFIG;
    my $candidate = eval { $JSON->decode(read_fixed($CONFIG, 128 * 1024)) };
    die "stored Makeover configuration is invalid: $@\n" if $@;
    return validate_config($candidate, 1);
}
sub checked_helper {
    assert_no_symlink($HELPER);
    my @st = stat($HELPER);
    die "branding helper is missing or unsafe\n" if !@st || !-f _ || !-x $HELPER
        || $st[4] != 0 || ($st[2] & 0022);
    return untaint_managed_path($HELPER);
}
sub helper_command {
    my (@arguments) = @_;
    my $stderr = '';
    eval {
        PVE::Tools::run_command([checked_helper(), @arguments], timeout => 60,
            outfunc => sub {}, errfunc => sub { $stderr .= substr($_[0], 0, 4096 - length($stderr)) if length($stderr) < 4096; });
        1;
    } or do {
        my $error = $@ || 'unknown helper failure';
        $stderr =~ s/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/?/g;
        die $stderr ? "branding helper failed: $stderr\n" : $error;
    };
}
sub run_helper {
    # Only the root API worker calls this while holding the shared API lock.
    helper_command('--lock-held');
}
sub validate_pixel_decode {
    my ($bytes, $kind) = @_;
    ensure_state();
    my ($fh, $path) = tempfile('.png-validate-XXXXXX', DIR => $STATE, UNLINK => 0);
    eval {
        binmode($fh);
        print {$fh} $bytes or die "write PNG validation input failed: $!\n";
        close($fh) or die "close PNG validation input failed: $!\n";
        helper_command('--validate-png', untaint_managed_path($path), '--kind', $kind eq 'logo' ? 'logo' : 'favicon');
        1;
    } or do {
        my $error = $@ || 'PNG decoding failed';
        close($fh) if defined(fileno($fh));
        unlink($path);
        die $error;
    };
    unlink($path) or die "remove PNG validation input failed: $!\n";
}
sub png_metadata {
    my ($bytes, $kind, $full_decode) = @_;
    $full_decode = 1 if !defined($full_decode);
    die "unsupported asset kind\n" if !defined($kind) || $kind !~ /\A(?:logo|favicon)\z/;
    die "PNG is empty\n" if !defined($bytes) || length($bytes) < 45;
    die "asset exceeds the 3 MiB limit\n" if length($bytes) > 3 * 1024 * 1024;
    die "asset is not a PNG\n" if substr($bytes, 0, 8) ne "\x89PNG\x0d\x0a\x1a\x0a";

    my $offset = 8;
    my ($width, $height, $seen_ihdr, $seen_iend, $seen_idat) = (0, 0, 0, 0, 0);
    while ($offset < length($bytes)) {
        die "truncated PNG chunk\n" if length($bytes) - $offset < 12;
        my $length = unpack('N', substr($bytes, $offset, 4));
        my $type = substr($bytes, $offset + 4, 4);
        die "invalid PNG chunk type\n" if $type !~ /\A[A-Za-z]{4}\z/;
        die "oversized or truncated PNG chunk\n" if $length > 3 * 1024 * 1024 || $offset + 12 + $length > length($bytes);
        my $data = substr($bytes, $offset + 8, $length);
        my $expected_crc = unpack('N', substr($bytes, $offset + 8 + $length, 4));
        my $actual_crc = crc32($type . $data);
        die "PNG CRC check failed\n" if $actual_crc != $expected_crc;

        if (!$seen_ihdr) {
            die "PNG does not start with IHDR\n" if $type ne 'IHDR' || $length != 13;
            ($width, $height) = unpack('NN', substr($data, 0, 8));
            my ($depth, $color, $compression, $filter, $interlace) = unpack('CCCCC', substr($data, 8, 5));
            die "invalid PNG dimensions\n" if $width < 64 || $height < 64 || $width > 4096 || $height > 4096;
            die "unsupported PNG encoding\n" if $compression != 0 || $filter != 0 || $interlace > 1;
            die "unsupported PNG color type\n" if $color !~ /\A(?:0|2|3|4|6)\z/;
            die "unsupported PNG bit depth\n" if $depth !~ /\A(?:1|2|4|8|16)\z/;
            $seen_ihdr = 1;
        } elsif ($type eq 'IHDR') {
            die "duplicate PNG IHDR\n";
        }

        $seen_idat = 1 if $type eq 'IDAT';
        if ($type eq 'IEND') {
            die "invalid PNG IEND\n" if $length != 0;
            $seen_iend = 1;
            $offset += 12;
            last;
        }
        $offset += 12 + $length;
    }
    die "PNG is missing IEND\n" if !$seen_iend;
    die "PNG is missing IDAT\n" if !$seen_idat;
    die "PNG contains trailing data\n" if $offset != length($bytes);
    die "favicon must be square\n" if $kind eq 'favicon' && $width != $height;

    validate_pixel_decode($bytes, $kind) if $full_decode;
    return {
        bytes => length($bytes),
        width => $width,
        height => $height,
        sha256 => sha256_hex($bytes),
    };
}

sub asset_path {
    my ($kind) = @_;
    die "unsupported asset kind\n" if !defined($kind) || $kind !~ /\A(?:logo|favicon)\z/;
    my $path = "$ASSET_ROOT/" . ($kind eq 'logo' ? 'SLS_Proxmox.png' : 'SLS_Proxmox_Favicon.png');
    assert_no_symlink($path);
    return $path;
}
sub managed_path { return $_[0] eq 'config' ? $CONFIG : asset_path($_[0]); }
sub state_payload {
    my $config = read_config();
    my $assets = {};
    for my $kind (qw(logo favicon)) {
        $assets->{$kind} = png_metadata(read_fixed(asset_path($kind), 3 * 1024 * 1024), $kind, 0);
    }
    my $rpcenv = PVE::RPCEnvironment::get();
    my $can_modify = $rpcenv->check($rpcenv->get_user(), '/', ['Sys.Modify'], 1);
    return {
        config => $config, assets => $assets, version => '0.1-beta',
        can_modify => $can_modify ? JSON::PP::true : JSON::PP::false,
        font_selection => JSON::PP::true,
        revision => sha256_hex($JSON->encode($config) . $assets->{logo}->{sha256} . $assets->{favicon}->{sha256}),
    };
}
sub reject_maintenance {
    assert_no_symlink($MAINTENANCE);
    return if !-e $MAINTENANCE;
    my @st = lstat($MAINTENANCE);
    die "unsafe Makeover maintenance marker; operator review required\n"
        if !@st || !-f _ || $st[4] != 0 || ($st[2] & 0777) != 0600;
    raise('Makeover is being updated; retry shortly.', code => 503);
}
sub with_lock {
    my ($code) = @_;
    assert_no_symlink($LOCK);
    ensure_directory(dirname($LOCK), 0700);
    chmod(0700, dirname($LOCK)) or die "cannot protect Makeover control directory: $!\n";
    sysopen(my $lock, $LOCK, O_WRONLY | O_CREAT | O_NOFOLLOW, 0600) or die "open Makeover lock failed: $!\n";
    die "unsafe Makeover lock\n" if !-f $lock || (stat($lock))[4] != 0;
    flock($lock, LOCK_EX) or die "lock Makeover state failed: $!\n";
    reject_maintenance();
    return $code->();
}
sub snapshot {
    my %snapshot;
    for my $key (qw(config logo favicon)) {
        my $path = managed_path($key);
        assert_no_symlink($path);
        $snapshot{$key} = -e $path ? read_fixed($path, $key eq 'config' ? 128 * 1024 : 3 * 1024 * 1024) : undef;
    }
    return \%snapshot;
}
sub preserve_snapshot {
    my ($old, $user) = @_;
    ensure_state();
    my $root = "$STATE/backups";
    ensure_directory($root, 0700);
    my $temporary = tempdir('.pending-XXXXXX', DIR => $root, CLEANUP => 0);
    my $now = time();
    my $stamp = strftime('%Y%m%dT%H%M%SZ', gmtime($now)) . '-' . sprintf('%06d', ($now - int($now)) * 1000000);
    my $final = "$root/$stamp-" . substr(basename($temporary), 9);
    eval {
        my %files;
        for my $key (qw(config logo favicon)) {
            my $name = $key eq 'config' ? 'config.json' : "$key.png";
            $files{$name} = defined($old->{$key}) ? sha256_hex($old->{$key}) : undef;
            atomic_write("$temporary/$name", $old->{$key}, 0600) if defined($old->{$key});
        }
        atomic_write("$temporary/manifest.json", $JSON->encode({ version => 1, user => $user, files => \%files }), 0600);
        rename($temporary, $final) or die "commit backup set failed: $!\n";
        sync_directory($root);
        1;
    } or do {
        my $error = $@ || 'backup failed';
        remove_tree($temporary, { safe => 1 }) if -d $temporary;
        die $error;
    };
    return $final;
}
sub prune_backups {
    my $root = "$STATE/backups";
    assert_no_symlink($root);
    opendir(my $dh, $root) or die "open backup history failed: $!\n";
    my @sets = sort grep { /\A\d{8}T\d{6}Z-\d{6}-[A-Za-z0-9_-]+\z/ } readdir($dh);
    closedir($dh);
    while (@sets > 20) {
        my $path = untaint_managed_path("$root/" . shift(@sets));
        assert_no_symlink($path);
        opendir(my $set, $path) or die "open backup set failed: $!\n";
        my @files = grep { $_ ne '.' && $_ ne '..' } readdir($set);
        closedir($set);
        for my $name (@files) {
            die "unexpected backup content; manual cleanup required\n" if $name !~ /\A(config\.json|logo\.png|favicon\.png|manifest\.json)\z/;
            $name = $1;
            my $file = "$path/$name";
            assert_no_symlink($file);
            die "unexpected backup file type\n" if !-f $file;
        }
        unlink("$path/$_") or die "remove expired backup file failed: $!\n" for @files;
        rmdir($path) or die "remove expired backup set failed: $!\n";
    }
    sync_directory($root);
}
sub audit_event {
    my ($user, $action, $details) = @_;
    ensure_state();
    assert_no_symlink($AUDIT);
    my $old = -e $AUDIT ? read_fixed($AUDIT, 1024 * 1024) : '';
    my $line = $JSON->encode({timestamp => strftime('%Y-%m-%dT%H:%M:%SZ', gmtime()), user => $user, action => $action, details => $details}) . "\n";
    die "audit event is too large\n" if length($line) > 16384;
    if (length($old) + length($line) > 1024 * 1024) {
        for my $number (reverse 1 .. 3) {
            my $source = $number == 1 ? $AUDIT : "$AUDIT." . ($number - 1);
            my $target = "$AUDIT.$number";
            assert_no_symlink($source); assert_no_symlink($target);
            atomic_write($target, read_fixed($source, 1024 * 1024), 0600) if -e $source;
        }
        $old = '';
    }
    atomic_write($AUDIT, $old . $line, 0600);
}
sub require_revision {
    my ($revision) = @_;
    die "expected_revision must contain the revision from the latest configuration read\n"
        if !defined($revision) || ref($revision) || $revision !~ /\A[0-9a-f]{64}\z/;
}
sub upload_now { return int(time()); }
sub upload_root {
    ensure_state();
    my $path = "$STATE/uploads";
    ensure_directory($path, 0700);
    chmod(0700, $path) or die "secure upload staging directory failed: $!\n";
    return $path;
}
sub upload_path {
    my ($id) = @_;
    die "invalid upload_id\n" if !defined($id) || ref($id) || $id !~ /\A([0-9a-f]{32})\z/;
    my $safe = $1;
    my $path = upload_root() . "/$safe";
    assert_no_symlink($path);
    return $path;
}
sub upload_files {
    my ($path) = @_;
    assert_no_symlink($path);
    my @st = lstat($path);
    die "unsafe upload staging directory\n" if !@st || !-d _ || $st[4] != 0 || ($st[2] & 0777) != 0700;
    opendir(my $dh, $path) or die "read upload staging directory failed: $!\n";
    my @files = grep { $_ ne '.' && $_ ne '..' } readdir($dh);
    closedir($dh);
    my $size = 0;
    for my $name (@files) {
        die "unexpected upload staging content; operator review required\n"
            if $name !~ /\A(metadata\.json|data\.png|\.sll-makeover-[A-Za-z0-9_-]+)\z/;
        $name = $1;
        my $file = "$path/$name";
        assert_no_symlink($file);
        my @info = lstat($file);
        die "unsafe upload staging file\n" if !@info || !-f _ || $info[4] != 0 || ($info[2] & 0777) != 0600;
        $size += $info[7];
    }
    return (\@files, $size);
}
sub remove_upload {
    my ($id) = @_;
    my $path = upload_path($id);
    return if !-e $path;
    my ($files) = upload_files($path);
    unlink("$path/$_") or die "remove staged upload file failed: $!\n" for @$files;
    rmdir($path) or die "remove staged upload directory failed: $!\n";
    sync_directory(upload_root());
}
sub upload_metadata {
    my ($id) = @_;
    my $path = upload_path($id);
    die "upload is unavailable; stage the PNG again\n" if !-d $path;
    upload_files($path);
    my $metadata = eval { $JSON->decode(read_fixed("$path/metadata.json", 4096)) };
    die "invalid upload staging metadata\n" if $@ || ref($metadata) ne 'HASH';
    my %allowed = map { $_ => 1 } qw(user kind expected_revision total_size received next_index created_at complete sha256);
    die "invalid upload staging metadata\n" if keys(%$metadata) != keys(%allowed) || grep { !$allowed{$_} } keys %$metadata;
    die "invalid upload staging binding\n" if !defined($metadata->{user}) || ref($metadata->{user})
        || !defined($metadata->{kind}) || $metadata->{kind} !~ /\A(?:logo|favicon)\z/
        || !defined($metadata->{expected_revision}) || $metadata->{expected_revision} !~ /\A[0-9a-f]{64}\z/;
    for my $key (qw(total_size received next_index created_at)) {
        die "invalid upload staging numeric field\n" if !defined($metadata->{$key}) || ref($metadata->{$key}) || "$metadata->{$key}" !~ /\A[0-9]+\z/;
    }
    die "invalid upload staging size\n" if $metadata->{total_size} < 1 || $metadata->{total_size} > $UPLOAD_MAX
        || $metadata->{received} > $metadata->{total_size} || $metadata->{next_index} > 32;
    validate_boolean('complete', $metadata->{complete});
    die "invalid completed upload checksum\n" if $metadata->{complete}
        && (!defined($metadata->{sha256}) || ref($metadata->{sha256}) || $metadata->{sha256} !~ /\A[0-9a-f]{64}\z/);
    return $metadata;
}
sub cleanup_uploads {
    # Called only under the shared API lock. Ignore no foreign directories:
    # unsafe names or symlinks require operator review, never recursive deletion.
    my $root = upload_root();
    opendir(my $dh, $root) or die "read upload history failed: $!\n";
    my @names = grep { $_ ne '.' && $_ ne '..' } readdir($dh);
    closedir($dh);
    my ($sessions, $bytes) = (0, 0);
    for my $id (@names) {
        die "unexpected upload staging directory; operator review required\n" if $id !~ /\A[0-9a-f]{32}\z/;
        my $path = upload_path($id);
        my (undef, $size) = upload_files($path);
        my $created = -f "$path/metadata.json" ? upload_metadata($id)->{created_at} : (stat($path))[9];
        if ($created + $UPLOAD_TTL <= upload_now()) { remove_upload($id); next; }
        $sessions++;
        $bytes += $size;
    }
    return ($sessions, $bytes);
}
sub new_upload_id {
    sysopen(my $fh, '/dev/urandom', O_RDONLY | O_NOFOLLOW) or die "open system random source failed: $!\n";
    my $random = '';
    while (length($random) < 16) {
        my $count = read($fh, my $part, 16 - length($random));
        die "read system random source failed\n" if !defined($count) || !$count;
        $random .= $part;
    }
    close($fh) or die "close system random source failed: $!\n";
    return unpack('H*', $random);
}
sub decode_upload_chunk {
    my ($encoded) = @_;
    die "invalid upload chunk base64\n" if !defined($encoded) || ref($encoded) || !length($encoded) || length($encoded) > 262144
        || $encoded !~ /\A(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\z/;
    my $bytes = decode_base64($encoded);
    die "upload chunk must contain 1 through 192 KiB\n" if !length($bytes) || length($bytes) > $UPLOAD_CHUNK;
    die "invalid canonical upload chunk base64\n" if encode_base64($bytes, '') ne $encoded;
    return $bytes;
}
sub stage_upload {
    my ($user, $param) = @_;
    require_revision($param->{expected_revision});
    my $kind = $param->{kind}; asset_path($kind);
    for my $key (qw(index total_size)) {
        die "invalid upload $key\n" if !defined($param->{$key}) || ref($param->{$key}) || "$param->{$key}" !~ /\A[0-9]+\z/;
    }
    die "invalid upload index\n" if $param->{index} > 31;
    die "upload total_size must be 1 through 3 MiB\n" if $param->{total_size} < 1 || $param->{total_size} > $UPLOAD_MAX;
    my $chunk = decode_upload_chunk($param->{content_base64});
    return with_lock(sub {
        my ($sessions, $bytes) = cleanup_uploads();
        my ($id, $metadata);
        if (defined($param->{upload_id})) {
            $id = $param->{upload_id};
            $metadata = upload_metadata($id);
            die "upload binding mismatch\n" if $metadata->{user} ne $user || $metadata->{kind} ne $kind
                || $metadata->{expected_revision} ne $param->{expected_revision} || $metadata->{total_size} != $param->{total_size};
            die "upload is already complete\n" if $metadata->{complete};
            die "upload chunks must arrive in order\n" if $metadata->{next_index} != $param->{index};
        } else {
            die "new uploads must start at index 0\n" if $param->{index} != 0;
            die "upload staging quota reached (8 sessions); finish an upload or retry after expiry\n" if $sessions >= 8;
        }
        raise('Makeover settings changed since upload started. Reload before staging artwork.', code => 409)
            if state_payload()->{revision} ne $param->{expected_revision};
        die "upload staging byte quota reached\n" if $bytes + length($chunk) > 32 * 1024 * 1024;
        my $old = defined($id) ? read_fixed(upload_path($id) . '/data.png', $UPLOAD_MAX) : '';
        die "upload staging length mismatch; stage the PNG again\n" if defined($metadata) && length($old) != $metadata->{received};
        my $data = $old . $chunk;
        die "upload chunk exceeds declared total_size\n" if length($data) > $param->{total_size};
        my $complete = length($data) == $param->{total_size};
        die "upload requires more than 32 chunks\n" if !$complete && $param->{index} == 31;
        my $png = $complete ? png_metadata($data, $kind, 1) : undef;
        if (!defined($id)) {
            for (1 .. 4) {
                $id = new_upload_id();
                my $candidate = upload_path($id);
                last if mkdir($candidate, 0700);
                $id = undef;
            }
            die "cannot create private upload session\n" if !defined($id);
            $metadata = {user => $user, kind => $kind, expected_revision => $param->{expected_revision},
                total_size => 0 + $param->{total_size}, received => 0, next_index => 0,
                created_at => upload_now(), complete => JSON::PP::false, sha256 => undef};
        }
        $metadata->{received} = length($data);
        $metadata->{next_index} = 1 + $param->{index};
        $metadata->{complete} = $complete ? JSON::PP::true : JSON::PP::false;
        $metadata->{sha256} = $complete ? $png->{sha256} : undef;
        my $path = upload_path($id);
        atomic_write("$path/data.png", $data, 0600);
        atomic_write("$path/metadata.json", $JSON->encode($metadata), 0600);
        return {upload_id => $id, complete => $metadata->{complete}, received => length($data),
            total_size => $metadata->{total_size}, next_index => $metadata->{next_index}};
    });
}
sub resolve_upload {
    my ($user, $kind, $expected, $id) = @_;
    my $metadata = upload_metadata($id);
    die "upload binding mismatch\n" if $metadata->{user} ne $user || $metadata->{kind} ne $kind || $metadata->{expected_revision} ne $expected;
    die "upload is not complete\n" if !$metadata->{complete} || $metadata->{received} != $metadata->{total_size};
    die "upload expired; stage the PNG again\n" if $metadata->{created_at} + $UPLOAD_TTL <= upload_now();
    my $data = read_fixed(upload_path($id) . '/data.png', $UPLOAD_MAX);
    die "staged upload integrity mismatch\n" if length($data) != $metadata->{total_size} || sha256_hex($data) ne $metadata->{sha256};
    png_metadata($data, $kind, 1);
    return $data;
}
sub check_inline_budget {
    my ($param) = @_;
    my $size = length($param->{config_json} // '');
    $size += length($param->{$_} // '') for qw(logo_base64 favicon_base64 content_base64);
    # Even worst-case percent encoding stays under the vendor 512 KiB limit.
    die "inline artwork request is too large; use the chunked upload endpoint\n" if $size > 128 * 1024;
}
sub transact {
    my ($user, $expected, $changes, $action, $uploads) = @_;
    $uploads //= {};
    require_revision($expected);
    return with_lock(sub {
        my $before = state_payload();
        raise('Makeover settings changed since they were loaded. Reload before applying.', code => 409)
            if $before->{revision} ne $expected;
        my %all_changes = %$changes;
        cleanup_uploads() if keys %$uploads;
        $all_changes{$_} = resolve_upload($user, $_, $expected, $uploads->{$_}) for keys %$uploads;
        my $old = snapshot();
        my $backup = preserve_snapshot($old, $user);
        prune_backups();
        my ($result, $write_started);
        eval {
            for my $key (sort keys %all_changes) {
                $write_started = 1;
                atomic_write(managed_path($key), $all_changes{$key}, $key eq 'config' ? 0600 : 0644);
            }
            run_helper();
            $result = state_payload();
            audit_event($user, $action, {before_revision => $before->{revision}, after_revision => $result->{revision}, backup => basename($backup)});
            1;
        } or do {
            my $error = $@ || 'unknown transaction failure';
            my @failures;
            if ($write_started) {
                for my $key (qw(config logo favicon)) {
                    eval {
                        my $path = managed_path($key);
                        if (defined($old->{$key})) {
                            atomic_write($path, $old->{$key}, $key eq 'config' ? 0600 : 0644);
                        } else {
                            assert_no_symlink($path);
                            unlink($path) or die "remove newly created $key failed: $!\n" if -e $path;
                            sync_directory(dirname($path));
                        }
                        1;
                    } or push @failures, "$key restore: " . ($@ || 'unknown failure');
                }
                eval { run_helper(); 1 } or push @failures, 'presentation reapply: ' . ($@ || 'unknown failure');
            }
            eval { audit_event($user, 'rollback', {error => substr("$error", 0, 2048), backup => basename($backup), incomplete => @failures ? JSON::PP::true : JSON::PP::false}); 1 }
                or push @failures, 'rollback audit: ' . ($@ || 'unknown failure');
            die "Makeover apply failed: $error\n" . (@failures
                ? "Rollback requires operator review: " . join('; ', @failures) . "\nRecovery backup: $backup\n"
                : "Previous configuration and artwork restored. Recovery backup: $backup\n");
        };
        my @warnings;
        for my $id (values %$uploads) {
            eval { remove_upload($id); 1 } or push @warnings, 'Saved successfully; consumed upload cleanup requires operator review.';
        }
        $result->{warnings} = \@warnings if @warnings;
        return $result;
    });
}
sub parse_config {
    my ($raw) = @_;
    die "configuration JSON is too large\n" if !defined($raw) || ref($raw) || length($raw) > 65536;
    my $candidate = eval { $JSON->decode($raw) };
    die "invalid configuration JSON: $@\n" if $@;
    return JSON::PP->new->utf8->canonical->pretty->encode(validate_config($candidate, 0));
}
sub decode_asset {
    my ($encoded, $kind) = @_;
    die "invalid base64 $kind asset\n" if !defined($encoded) || ref($encoded) || length($encoded) > 131072
        || $encoded !~ /\A(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\z/;
    my $bytes = decode_base64($encoded);
    png_metadata($bytes, $kind, 1);
    return $bytes;
}
my $REVISION_SCHEMA = {type => 'string', pattern => '^[0-9a-f]{64}$', minLength => 64, maxLength => 64};
__PACKAGE__->register_method({
    name => 'index', path => '', method => 'GET', protected => 1,
    permissions => {check => ['perm', '/', ['Sys.Audit']]},
    description => 'Directory index for Proxmox Makeover by Southland Labs.',
    parameters => {additionalProperties => 0, properties => {}},
    returns => {type => 'array', items => {type => 'object', properties => {subdir => {type => 'string'}}}, links => [{rel => 'child', href => '{subdir}'}]},
    code => sub { require_interactive_user(); return [{subdir => 'config'}, {subdir => 'asset'}, {subdir => 'upload'}, {subdir => 'apply'}]; },
});
__PACKAGE__->register_method({
    name => 'get_config', path => 'config', method => 'GET', protected => 1,
    permissions => {check => ['perm', '/', ['Sys.Audit']]},
    description => 'Read the safe Proxmox Makeover presentation configuration.',
    parameters => {additionalProperties => 0, properties => {}}, returns => {type => 'object'},
    code => sub { require_interactive_user(); return with_lock(sub { state_payload() }); },
});
__PACKAGE__->register_method({
    name => 'update_config', path => 'config', method => 'PUT', protected => 1,
    permissions => {check => ['perm', '/', ['Sys.Modify']]},
    description => 'Update bounded presentation settings with revision checking.',
    parameters => {additionalProperties => 0, properties => {
        config_json => {type => 'string', minLength => 2, maxLength => 65536}, expected_revision => $REVISION_SCHEMA,
    }}, returns => {type => 'object'},
    code => sub { my ($param) = @_; my $user = require_interactive_user();
        return transact($user, $param->{expected_revision}, {config => parse_config($param->{config_json})}, 'config-update'); },
});
__PACKAGE__->register_method({
    name => 'upload_asset', path => 'asset', method => 'POST', protected => 1,
    permissions => {check => ['perm', '/', ['Sys.Modify']]},
    description => 'Replace a logo or favicon using bounded fully decoded PNG validation.',
    parameters => {additionalProperties => 0, properties => {
        kind => {type => 'string', enum => ['logo', 'favicon']},
        content_base64 => {type => 'string', minLength => 16, maxLength => 131072}, expected_revision => $REVISION_SCHEMA,
    }}, returns => {type => 'object'},
    code => sub { my ($param) = @_; my $user = require_interactive_user();
        my $kind = $param->{kind}; asset_path($kind); check_inline_budget($param);
        return transact($user, $param->{expected_revision}, {$kind => decode_asset($param->{content_base64}, $kind)}, 'asset-update'); },
});
__PACKAGE__->register_method({
    name => 'upload', path => 'upload', method => 'POST', protected => 1,
    permissions => {check => ['perm', '/', ['Sys.Modify']]},
    description => 'Stage ordered PNG chunks below the native request limit. Canonical artwork changes only on apply.',
    parameters => {additionalProperties => 0, properties => {
        kind => {type => 'string', enum => ['logo', 'favicon']}, expected_revision => $REVISION_SCHEMA,
        upload_id => {type => 'string', optional => 1, pattern => '^[0-9a-f]{32}$', minLength => 32, maxLength => 32},
        index => {type => 'integer', minimum => 0, maximum => 31},
        total_size => {type => 'integer', minimum => 1, maximum => 3145728},
        content_base64 => {type => 'string', minLength => 4, maxLength => 262144},
    }}, returns => {type => 'object'},
    code => sub { my ($param) = @_; my $user = require_interactive_user(); return stage_upload($user, $param); },
});
__PACKAGE__->register_method({
    name => 'apply', path => 'apply', method => 'PUT', protected => 1,
    permissions => {check => ['perm', '/', ['Sys.Modify']]},
    description => 'Apply validated settings and PNGs with backups, revision checking and rollback.',
    parameters => {additionalProperties => 0, properties => {
        config_json => {type => 'string', minLength => 2, maxLength => 65536}, expected_revision => $REVISION_SCHEMA,
        logo_base64 => {type => 'string', optional => 1, minLength => 16, maxLength => 131072},
        logo_upload_id => {type => 'string', optional => 1, pattern => '^[0-9a-f]{32}$', minLength => 32, maxLength => 32},
        favicon_base64 => {type => 'string', optional => 1, minLength => 16, maxLength => 131072},
        favicon_upload_id => {type => 'string', optional => 1, pattern => '^[0-9a-f]{32}$', minLength => 32, maxLength => 32},
    }}, returns => {type => 'object'},
    code => sub { my ($param) = @_; my $user = require_interactive_user();
        check_inline_budget($param);
        my %changes = (config => parse_config($param->{config_json}));
        my %uploads;
        for my $kind (qw(logo favicon)) {
            die "choose an inline PNG or staged upload for $kind, not both\n"
                if defined($param->{"${kind}_base64"}) && defined($param->{"${kind}_upload_id"});
            $changes{$kind} = decode_asset($param->{"${kind}_base64"}, $kind) if defined($param->{"${kind}_base64"});
            $uploads{$kind} = $param->{"${kind}_upload_id"} if defined($param->{"${kind}_upload_id"});
        }
        return transact($user, $param->{expected_revision}, \%changes, 'apply', \%uploads); },
});
1;
