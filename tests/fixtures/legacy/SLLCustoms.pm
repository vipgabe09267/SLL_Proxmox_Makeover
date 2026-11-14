package PVE::API2::SLLCustoms;

use strict;
use warnings;

use Compress::Zlib qw(crc32);
use Digest::SHA qw(sha256_hex);
use Fcntl qw(:flock);
use File::Basename qw(dirname);
use File::Path qw(make_path);
use File::Temp qw(tempfile);
use JSON::PP;
use MIME::Base64 qw(decode_base64);
use POSIX qw(strftime);
use URI;

use PVE::JSONSchema;
use PVE::RESTHandler;
use PVE::RPCEnvironment;
use PVE::Tools;

use base qw(PVE::RESTHandler);

my $CONFIG = '/etc/sll-proxmox-makeover/config.json';
my $ASSET_ROOT = '/usr/local/share/sls-proxmox-branding/assets';
my $HELPER = '/usr/local/sbin/sls-proxmox-branding';
my $LOCK = '/run/lock/sll-proxmox-makeover.lock';
my $STATE = '/var/lib/sll-proxmox-makeover';
my $AUDIT = "$STATE/audit.jsonl";

my $JSON = JSON::PP->new->utf8->canonical->allow_nonref(0)->max_depth(20);

my $DEFAULT = {
    schema_version => 1,
    company_name => 'Southland Labs',
    project_name => 'Proxmox Makeover',
    product_label => 'Proxmox VE',
    page_title => 'Infrastructure - Southland Labs | Proxmox VE',
    login_eyebrow => 'Infrastructure console',
    login_heading => 'Welcome back.',
    login_subtitle => 'Sign in to manage your infrastructure.',
    footer_text => 'Southland Labs',
    website_url => 'https://southlandlabs.dev/',
    show_storage_panel => 1,
    colors => {
        background => '#141716',
        surface => '#1b201e',
        raised => '#242b26',
        border => '#343c36',
        accent => '#d5b98c',
        secondary => '#bac8ad',
        text => '#eeede6',
        muted => '#a5ada7',
    },
};

my @TEXT_KEYS = qw(
    company_name project_name product_label page_title login_eyebrow login_heading
    login_subtitle footer_text
);
my %TEXT_MAX = (
    company_name => 80,
    project_name => 80,
    product_label => 80,
    page_title => 160,
    login_eyebrow => 100,
    login_heading => 100,
    login_subtitle => 240,
    footer_text => 120,
);
my @COLOR_KEYS = qw(background surface raised border accent secondary text muted);

sub clone_default {
    return $JSON->decode($JSON->encode($DEFAULT));
}

sub require_interactive_user {
    my $rpcenv = PVE::RPCEnvironment::get();
    my $authid = $rpcenv->get_user() // '';
    die "interactive Proxmox login required\n" if !$authid || $authid =~ /!/;
    return $authid;
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
    die "website_url contains whitespace or control characters\n" if $value =~ /[\s\x00-\x1f\x7f]/;
    my $uri = URI->new($value);
    die "website_url must be an HTTPS URL\n" if lc($uri->scheme // '') ne 'https';
    die "website_url must include a hostname\n" if !defined($uri->host) || $uri->host !~ /\A[a-z0-9.-]+\z/i;
    die "website_url must not include user information\n" if defined($uri->userinfo);
    return $uri->as_string;
}

sub validate_config {
    my ($candidate) = @_;
    die "configuration must be an object\n" if ref($candidate) ne 'HASH';

    my %allowed = map { $_ => 1 } ('schema_version', @TEXT_KEYS, 'website_url', 'show_storage_panel', 'colors');
    for my $key (keys %$candidate) {
        die "unknown configuration field '$key'\n" if !$allowed{$key};
    }

    my $clean = clone_default();
    die "unsupported schema_version\n"
        if defined($candidate->{schema_version}) && $candidate->{schema_version} != 1;
    $clean->{$_} = validate_text($_, $candidate->{$_}) for @TEXT_KEYS;
    $clean->{website_url} = validate_url($candidate->{website_url});

    my $show = $candidate->{show_storage_panel};
    die "show_storage_panel must be true or false\n"
        if !defined($show) || ref($show) && ref($show) ne 'JSON::PP::Boolean';
    die "show_storage_panel must be true or false\n"
        if !ref($show) && "$show" !~ /\A(?:0|1)\z/;
    $clean->{show_storage_panel} = $show ? JSON::PP::true : JSON::PP::false;

    die "colors must be an object\n" if ref($candidate->{colors}) ne 'HASH';
    my %allowed_color = map { $_ => 1 } @COLOR_KEYS;
    for my $key (keys %{$candidate->{colors}}) {
        die "unknown color field '$key'\n" if !$allowed_color{$key};
    }
    for my $key (@COLOR_KEYS) {
        my $color = $candidate->{colors}->{$key};
        die "invalid color '$key'\n" if !defined($color) || ref($color) || $color !~ /\A#[0-9a-fA-F]{6}\z/;
        $clean->{colors}->{$key} = lc($color);
    }
    return $clean;
}

sub untaint_managed_path {
    my ($path) = @_;
    die "unsafe managed path\n"
        if !defined($path) || $path =~ m{(?:\A|/)\.\.(?:/|\z)} || $path !~ m{\A(/[A-Za-z0-9_./-]+)\z};
    return $1;
}

sub atomic_write {
    my ($path, $data, $mode) = @_;
    $path = untaint_managed_path($path);
    assert_no_symlink($path);
    my $dir = dirname($path);
    make_path($dir, { mode => 0700 }) if !-d $dir;
    my ($fh, $temporary) = tempfile('.sll-makeover-XXXXXX', DIR => $dir, UNLINK => 0);
    binmode($fh);
    print {$fh} $data or die "write $temporary failed: $!\n";
    $fh->flush() or die "flush $temporary failed: $!\n";
    chmod($mode, $temporary) or die "chmod $temporary failed: $!\n";
    close($fh) or die "close $temporary failed: $!\n";
    rename($temporary, $path) or die "rename $temporary to $path failed: $!\n";
}

sub assert_no_symlink {
    my ($path) = @_;
    die "internal path must be absolute\n" if !defined($path) || $path !~ m{\A/};
    my $current = '';
    for my $part (grep { length($_) } split(m{/+}, $path)) {
        $current .= "/$part";
        die "refusing symlink in managed path\n" if -l $current;
    }
    return 1;
}

sub preserve_backup {
    my ($label, $data) = @_;
    my $backup_dir = "$STATE/backups";
    make_path($backup_dir, { mode => 0700 }) if !-d $backup_dir;
    my $stamp = strftime('%Y%m%dT%H%M%SZ', gmtime());
    my $safe_label = $label;
    $safe_label =~ s/[^A-Za-z0-9_.-]+/-/g;
    my $path = "$backup_dir/$stamp-$safe_label-" . substr(sha256_hex($data), 0, 16);
    atomic_write($path, $data, 0600) if !-e $path;
    return $path;
}

sub read_config {
    assert_no_symlink($CONFIG);
    return clone_default() if !-f $CONFIG;
    my $raw = PVE::Tools::file_get_contents($CONFIG, 128 * 1024);
    my $decoded = eval { $JSON->decode($raw) };
    die "stored Makeover configuration is invalid: $@\n" if $@;
    return validate_config($decoded);
}

sub png_metadata {
    my ($bytes, $kind) = @_;
    die "PNG is empty\n" if !defined($bytes) || length($bytes) < 45;
    die "asset exceeds the 3 MiB limit\n" if length($bytes) > 3 * 1024 * 1024;
    die "asset is not a PNG\n" if substr($bytes, 0, 8) ne "\x89PNG\x0d\x0a\x1a\x0a";

    my $offset = 8;
    my ($width, $height, $seen_ihdr, $seen_iend) = (0, 0, 0, 0);
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

        if ($type eq 'IEND') {
            die "invalid PNG IEND\n" if $length != 0;
            $seen_iend = 1;
            $offset += 12;
            last;
        }
        $offset += 12 + $length;
    }
    die "PNG is missing IEND\n" if !$seen_iend;
    die "PNG contains trailing data\n" if $offset != length($bytes);
    die "favicon must be square\n" if $kind eq 'favicon' && $width != $height;

    return {
        bytes => length($bytes),
        width => $width,
        height => $height,
        sha256 => sha256_hex($bytes),
    };
}

sub asset_path {
    my ($kind) = @_;
    my $path;
    $path = "$ASSET_ROOT/SLS_Proxmox.png" if $kind eq 'logo';
    $path = "$ASSET_ROOT/SLS_Proxmox_Favicon.png" if $kind eq 'favicon';
    if (defined($path)) {
        assert_no_symlink($path);
        return $path;
    }
    die "unsupported asset kind\n";
}

sub state_payload {
    my $config = read_config();
    my $config_json = $JSON->encode($config);
    my $assets = {};
    for my $kind (qw(logo favicon)) {
        my $path = asset_path($kind);
        my $bytes = PVE::Tools::file_get_contents($path, 3 * 1024 * 1024 + 1);
        $assets->{$kind} = png_metadata($bytes, $kind);
    }
    return {
        config => $config,
        assets => $assets,
        revision => sha256_hex($config_json . $assets->{logo}->{sha256} . $assets->{favicon}->{sha256}),
        version => '0.1.0',
    };
}

sub with_lock {
    my ($code) = @_;
    assert_no_symlink($LOCK);
    open(my $lock, '>>', $LOCK) or die "open $LOCK failed: $!\n";
    flock($lock, LOCK_EX) or die "lock $LOCK failed: $!\n";
    return $code->();
}

sub audit_event {
    my ($user, $action, $details) = @_;
    make_path($STATE, { mode => 0700 }) if !-d $STATE;
    my $record = {
        timestamp => strftime('%Y-%m-%dT%H:%M:%SZ', gmtime()),
        user => $user,
        action => $action,
        details => $details,
    };
    assert_no_symlink($AUDIT);
    open(my $fh, '>>', $AUDIT) or die "open $AUDIT failed: $!\n";
    chmod(0600, $AUDIT);
    print {$fh} $JSON->encode($record), "\n" or die "write audit log failed: $!\n";
    close($fh) or die "close audit log failed: $!\n";
}

sub run_helper {
    die "branding helper is missing\n" if !-x $HELPER;
    my $stderr = '';
    eval {
        PVE::Tools::run_command(
            [$HELPER],
            timeout => 60,
            outfunc => sub {},
            errfunc => sub {
                $stderr .= $_[0] . "\n" if length($stderr) < 4096;
            },
        );
        1;
    } or do {
        my $error = $@ || 'unknown helper failure';
        $stderr =~ s/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/?/g;
        die $stderr ? "branding helper failed: $stderr" : $error;
    };
}

__PACKAGE__->register_method({
    name => 'index',
    path => '',
    method => 'GET',
    protected => 1,
    permissions => { check => ['perm', '/', ['Sys.Audit']] },
    description => 'Directory index for Proxmox Makeover by Southland Labs.',
    parameters => { additionalProperties => 0, properties => {} },
    returns => {
        type => 'array',
        items => { type => 'object', properties => { subdir => { type => 'string' } } },
        links => [{ rel => 'child', href => '{subdir}' }],
    },
    code => sub {
        require_interactive_user();
        return [{ subdir => 'config' }, { subdir => 'asset' }, { subdir => 'apply' }];
    },
});

__PACKAGE__->register_method({
    name => 'get_config',
    path => 'config',
    method => 'GET',
    protected => 1,
    permissions => { check => ['perm', '/', ['Sys.Audit']] },
    description => 'Read the safe Proxmox Makeover presentation configuration.',
    parameters => { additionalProperties => 0, properties => {} },
    returns => { type => 'object' },
    code => sub {
        require_interactive_user();
        return state_payload();
    },
});

__PACKAGE__->register_method({
    name => 'update_config',
    path => 'config',
    method => 'PUT',
    protected => 1,
    permissions => { check => ['perm', '/', ['Sys.Modify']] },
    description => 'Update the validated Proxmox Makeover presentation configuration.',
    parameters => {
        additionalProperties => 0,
        properties => {
            config_json => { type => 'string', minLength => 2, maxLength => 65536 },
        },
    },
    returns => { type => 'object' },
    code => sub {
        my ($param) = @_;
        my $user = require_interactive_user();
        my $candidate = eval { $JSON->decode($param->{config_json}) };
        die "invalid configuration JSON: $@\n" if $@;
        my $clean = validate_config($candidate);
        my $encoded = JSON::PP->new->utf8->canonical->pretty->encode($clean);

        return with_lock(sub {
            my $old = -f $CONFIG ? PVE::Tools::file_get_contents($CONFIG, 128 * 1024) : undef;
            my $old_hash = defined($old) ? sha256_hex($old) : undef;
            preserve_backup('config.json', $old) if defined($old);
            atomic_write($CONFIG, $encoded, 0600);
            eval { run_helper(); 1 } or do {
                my $error = $@ || 'unknown helper failure';
                defined($old) ? atomic_write($CONFIG, $old, 0600) : unlink($CONFIG);
                eval { run_helper(); };
                die "configuration was rolled back because branding activation failed: $error";
            };
            audit_event($user, 'config-update', {
                before_sha256 => $old_hash,
                after_sha256 => sha256_hex($encoded),
            });
            return state_payload();
        });
    },
});

__PACKAGE__->register_method({
    name => 'upload_asset',
    path => 'asset',
    method => 'POST',
    protected => 1,
    permissions => { check => ['perm', '/', ['Sys.Modify']] },
    description => 'Replace a Proxmox Makeover logo or favicon with a validated PNG.',
    parameters => {
        additionalProperties => 0,
        properties => {
            kind => { type => 'string', enum => ['logo', 'favicon'] },
            content_base64 => { type => 'string', minLength => 16, maxLength => 4300000 },
        },
    },
    returns => { type => 'object' },
    code => sub {
        my ($param) = @_;
        my $user = require_interactive_user();
        my $encoded = $param->{content_base64};
        die "invalid base64 asset\n"
            if $encoded !~ /\A(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\z/;
        my $bytes = decode_base64($encoded);
        my $metadata = png_metadata($bytes, $param->{kind});
        my $path = asset_path($param->{kind});

        return with_lock(sub {
            my $old = PVE::Tools::file_get_contents($path, 3 * 1024 * 1024 + 1);
            my $old_metadata = png_metadata($old, $param->{kind});
            preserve_backup("$param->{kind}.png", $old);
            atomic_write($path, $bytes, 0644);
            eval { run_helper(); 1 } or do {
                my $error = $@ || 'unknown helper failure';
                atomic_write($path, $old, 0644);
                eval { run_helper(); };
                die "asset was rolled back because branding activation failed: $error";
            };
            audit_event($user, 'asset-update', {
                kind => $param->{kind},
                before_sha256 => $old_metadata->{sha256},
                after_sha256 => $metadata->{sha256},
                width => $metadata->{width},
                height => $metadata->{height},
            });
            return state_payload();
        });
    },
});

__PACKAGE__->register_method({
    name => 'apply',
    path => 'apply',
    method => 'PUT',
    protected => 1,
    permissions => { check => ['perm', '/', ['Sys.Modify']] },
    description => 'Atomically apply validated Makeover settings and optional PNG assets.',
    parameters => {
        additionalProperties => 0,
        properties => {
            config_json => { type => 'string', minLength => 2, maxLength => 65536 },
            logo_base64 => { type => 'string', optional => 1, minLength => 16, maxLength => 4300000 },
            favicon_base64 => { type => 'string', optional => 1, minLength => 16, maxLength => 4300000 },
        },
    },
    returns => { type => 'object' },
    code => sub {
        my ($param) = @_;
        my $user = require_interactive_user();
        my $candidate = eval { $JSON->decode($param->{config_json}) };
        die "invalid configuration JSON: $@\n" if $@;
        my $clean = validate_config($candidate);
        my $new_config = JSON::PP->new->utf8->canonical->pretty->encode($clean);

        my %new_asset;
        for my $kind (qw(logo favicon)) {
            my $key = "${kind}_base64";
            next if !defined($param->{$key});
            my $encoded = $param->{$key};
            die "invalid base64 $kind asset\n"
                if $encoded !~ /\A(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\z/;
            my $bytes = decode_base64($encoded);
            $new_asset{$kind} = {
                bytes => $bytes,
                metadata => png_metadata($bytes, $kind),
            };
        }

        return with_lock(sub {
            my $old_config = -f $CONFIG ? PVE::Tools::file_get_contents($CONFIG, 128 * 1024) : undef;
            my %old_asset;
            for my $kind (keys %new_asset) {
                my $path = asset_path($kind);
                my $bytes = PVE::Tools::file_get_contents($path, 3 * 1024 * 1024 + 1);
                $old_asset{$kind} = $bytes;
                preserve_backup("$kind.png", $bytes);
            }
            preserve_backup('config.json', $old_config) if defined($old_config);

            atomic_write($CONFIG, $new_config, 0600);
            atomic_write(asset_path($_), $new_asset{$_}->{bytes}, 0644) for keys %new_asset;
            eval { run_helper(); 1 } or do {
                my $error = $@ || 'unknown helper failure';
                defined($old_config) ? atomic_write($CONFIG, $old_config, 0600) : unlink($CONFIG);
                atomic_write(asset_path($_), $old_asset{$_}, 0644) for keys %old_asset;
                eval { run_helper(); };
                die "changes were rolled back because branding activation failed: $error";
            };

            my $assets = {};
            for my $kind (keys %new_asset) {
                $assets->{$kind} = {
                    before_sha256 => sha256_hex($old_asset{$kind}),
                    after_sha256 => $new_asset{$kind}->{metadata}->{sha256},
                    width => $new_asset{$kind}->{metadata}->{width},
                    height => $new_asset{$kind}->{metadata}->{height},
                };
            }
            audit_event($user, 'apply', {
                before_config_sha256 => defined($old_config) ? sha256_hex($old_config) : undef,
                after_config_sha256 => sha256_hex($new_config),
                assets => $assets,
            });
            return state_payload();
        });
    },
});

1;
