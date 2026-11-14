#!/usr/bin/perl
use strict;
use warnings;
use Test::More;
use File::Basename qw(dirname);
use Cwd qw(abs_path);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use JSON::PP;
use MIME::Base64 qw(encode_base64);
use Compress::Zlib qw(compress uncompress crc32);
use Digest::SHA qw(sha256_hex);
use HTTP::Request;
use Scalar::Util qw(tainted);

# Load the unmodified production module after redirecting only its fixed paths.
# No test loads a PVE service or references the host configuration/state.
our %METHODS;
our $USER = 'root@pam';
our $ENABLED_PAGE_USER = 1;
our $CAN_MODIFY = 1;
our $HELPER_CALLS = 0;
our $DECODE_CALLS = 0;
our $HELPER_FAILURES = 0;
our ($REAL_HELPER) = abs_path(dirname(__FILE__) . '/../sls-proxmox-branding') =~ /\A(\/[A-Za-z0-9_.\/-]+)\z/;
$ENV{PATH} = '/usr/bin:/bin';
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};
# Optional extracted decoder dependencies are single safe absolute directories.
for my $name (qw(LD_LIBRARY_PATH PYTHONPATH)) {
    next if !exists($ENV{$name});
    my ($safe) = $ENV{$name} =~ /\A(\/[A-Za-z0-9_.\/-]+)\z/;
    die "unsafe test decoder environment\n" if !defined($safe) || $safe =~ m{(?:^|/)\.\.(?:/|$)};
    $ENV{$name} = $safe;
}
BEGIN {
    package PVE::API2::SLLPasskeys;
    sub install_auth_hook { return 1; }
    $INC{'PVE/API2/SLLPasskeys.pm'} = 1;
    package PVE::API2;
    sub register_method { return 1; }
    $INC{'PVE/API2.pm'} = 1;
    package PVE::AccessControl;
    sub verify_ticket {
        return ({type => 'new', data => 'fixture'}) if $_[0] eq 'new-tfa-ticket';
        return ('root@pam', 0, {type => 'tfa'}) if $_[0] eq 'old-tfa-ticket';
        return ('root@pam', 0, {type => 'u2f', challenge => 'fixture'}) if $_[0] eq 'u2f-ticket';
        return $_[0] eq 'valid-ticket' ? ('root@pam', 0, undef) : ();
    }
    sub check_user_enabled { die 'disabled' if !$main::ENABLED_PAGE_USER; return 1; }
    $INC{'PVE/AccessControl.pm'} = 1;
    package PVE::Cluster;
    sub cfs_read_file { return {users => {'root@pam' => {enable => 1}}}; }
    $INC{'PVE/Cluster.pm'} = 1;
    package PVE::APIServer::Formatter;
    sub extract_auth_value { my ($cookie, $name) = @_; return $cookie =~ /(?:^|;\s*)\Q$name\E=([^;]+)/ ? $1 : undef; }
    $INC{'PVE/APIServer/Formatter.pm'} = 1;
    package PVE::JSONSchema;
    $INC{'PVE/JSONSchema.pm'} = 1;
    package PVE::RESTHandler;
    sub register_method { $main::METHODS{$_[1]->{name}} = $_[1]; }
    $INC{'PVE/RESTHandler.pm'} = 1;
    package PVE::RPCEnvironment;
    sub get { bless {}, __PACKAGE__ }
    sub get_user { $main::USER }
    sub check { $main::CAN_MODIFY }
    $INC{'PVE/RPCEnvironment.pm'} = 1;
    package PVE::Exception;
    use base 'Exporter';
    our @EXPORT_OK = qw(raise);
    sub raise { my ($message, %options) = @_; die "$options{code} $message\n"; }
    $INC{'PVE/Exception.pm'} = 1;
    package PVE::Tools;
    sub run_command {
        my ($argv) = @_;
        die "tainted subprocess argument\n" if grep { Scalar::Util::tainted($_) } @$argv;
        if ($argv->[1] eq '--validate-png') {
            $main::DECODE_CALLS++;
            die "unsafe decoder invocation\n" if @$argv != 5 || $argv->[3] ne '--kind' || $argv->[4] !~ /\A(?:logo|favicon)\z/;
            if ($ENV{MAKEOVER_TEST_REAL_HELPER}) {
                open(my $process, '-|', '/usr/bin/python3', $main::REAL_HELPER,
                    '--validate-png', $argv->[2], '--kind', $argv->[4]) or die "start packaged decoder: $!";
                local $/; my $output = <$process>;
                close($process) or die "PNG pixel decode failed\n";
                return;
            }
            # Unit stand-in for the packaged Pillow decoder: fully decompress the
            # test's RGBA scanlines, including failure for CRC-valid broken IDAT.
            my $bytes = main::read_bytes($argv->[2]);
            my ($offset, $compressed) = (8, '');
            while ($offset < length($bytes)) {
                my $length = unpack('N', substr($bytes, $offset, 4));
                my $type = substr($bytes, $offset + 4, 4);
                $compressed .= substr($bytes, $offset + 8, $length) if $type eq 'IDAT';
                $offset += 12 + $length;
            }
            my $pixels = Compress::Zlib::uncompress($compressed);
            die "PNG pixel decode failed\n" if !defined($pixels) || length($pixels) != 64 * (1 + 64 * 4);
        } else {
            die "helper must use held-lock entry point\n" if @$argv != 2 || $argv->[1] ne '--lock-held';
            $main::HELPER_CALLS++;
            if ($main::HELPER_FAILURES > 0) { $main::HELPER_FAILURES--; die "simulated activation failure\n"; }
        }
    }
    $INC{'PVE/Tools.pm'} = 1;
}

my $root = tempdir('makeover-api-XXXXXX', TMPDIR => 1, CLEANUP => 1);
my $source_path = dirname(__FILE__) . '/../PVE/API2/SLLCustoms.pm';
my $source = read_bytes($source_path);
$source =~ s{\Q/etc/sll-proxmox-makeover/config.json\E}{$root/etc/config.json}g;
$source =~ s{\Q/usr/local/share/sls-proxmox-branding/assets\E}{$root/assets}g;
$source =~ s{\Q/usr/local/sbin/sls-proxmox-branding\E}{$root/bin/helper}g;
$source =~ s{\Q/var/lib/proxmox-makeover/control.lock\E}{$root/run/makeover.lock}g;
$source =~ s{\Q/var/lib/proxmox-makeover/maintenance.json\E}{$root/run/makeover.maintenance}g;
$source =~ s{\Q/var/lib/sll-proxmox-makeover\E}{$root/state}g;
for my $path (qw(etc assets bin run state)) { make_path("$root/$path", {mode => 0700}); }
write_bytes("$root/bin/helper", "#!/bin/sh\nexit 0\n"); chmod(0755, "$root/bin/helper");
# Test-only whole-source untaint: the module content comes exclusively from
# this checked-out source and all server paths above point into our temp root.
my ($isolated_source) = $source =~ /\A([\s\S]*)\z/;
my $loaded = eval $isolated_source;
die "isolated API failed to load: $@" if !$loaded;

sub read_bytes { my ($path) = @_; open(my $fh, '<', $path) or die "read $path: $!"; binmode($fh); local $/; return <$fh>; }
sub write_bytes { my ($path, $bytes) = @_; open(my $fh, '>', $path) or die "write $path: $!"; binmode($fh); print {$fh} $bytes; close($fh); }
sub call_api { my ($name, $args) = @_; return $METHODS{$name}->{code}->($args // {}); }
sub error_from { my ($code) = @_; eval { $code->(); 1 }; return "$@"; }
sub chunk { my ($type, $bytes) = @_; return pack('N', length($bytes)) . $type . $bytes . pack('N', crc32($type . $bytes)); }
sub make_png {
    my ($rgba, $broken) = @_;
    my $rows = ("\0" . ($rgba x 64)) x 64;
    return "\x89PNG\r\n\x1a\n" . chunk('IHDR', pack('NNCCCCC', 64, 64, 8, 6, 0, 0, 0))
        . chunk('IDAT', $broken ? 'not compressed pixels' : compress($rows)) . chunk('IEND', '');
}
my $logo = make_png("\x44\x66\x88\xff");
my $favicon = make_png("\xaa\x88\x66\xff");
write_bytes("$root/assets/SLS_Proxmox.png", $logo);
write_bytes("$root/assets/SLS_Proxmox_Favicon.png", $favicon);
my $JSON = JSON::PP->new->canonical;
my $initial = PVE::API2::SLLCustoms::clone_default();
write_bytes("$root/etc/config.json", $JSON->encode($initial));
sub current { call_api('get_config'); }
sub apply_config {
    my ($config, $revision, %extra) = @_;
    return call_api('apply', {config_json => $JSON->encode($config), expected_revision => $revision, %extra});
}
sub canonical_snapshot {
    return join('', map { sha256_hex(read_bytes($_)) } ("$root/etc/config.json", "$root/assets/SLS_Proxmox.png", "$root/assets/SLS_Proxmox_Favicon.png"));
}

is(current()->{version}, '0.1-beta', 'beta version');
is(current()->{config}->{schema_version}, 2, 'schema two');
ok(current()->{config}->{update_safe}, 'update-safe defaults true');
ok(current()->{font_selection}, 'font selection capability advertised');
is_deeply(current()->{config}->{fonts}, {login => 'default', dashboard => 'default'}, 'default fonts retain current appearance');
for my $preset (qw(default system dm-sans oxanium serif monospace)) {
    my $candidate = PVE::API2::SLLCustoms::clone_default();
    $candidate->{fonts} = {login => $preset, dashboard => $preset};
    is_deeply(PVE::API2::SLLCustoms::validate_config($candidate, 0)->{fonts}, $candidate->{fonts}, 'local font preset accepted');
}
for my $value ('https://example.org/font.ttf', 'url(https://example.org)', 'serif; color:red', '__proto__', 'constructor', '', undef, [], {}, JSON::PP::true) {
    my $candidate = PVE::API2::SLLCustoms::clone_default(); $candidate->{fonts}->{login} = $value;
    like(error_from(sub { apply_config($candidate, current()->{revision}) }), qr/invalid font/, 'font CSS/URL/type injection rejected');
}
for my $fonts ({}, {login => 'default'}, {login => 'default', dashboard => 'default', url => 'https://example.org'}) {
    my $candidate = PVE::API2::SLLCustoms::clone_default(); $candidate->{fonts} = $fonts;
    like(error_from(sub { apply_config($candidate, current()->{revision}) }), qr/fonts must/, 'invalid font object rejected');
}
my $pre_font = PVE::API2::SLLCustoms::clone_default(); delete($pre_font->{fonts});
is_deeply(PVE::API2::SLLCustoms::validate_config($pre_font, 1)->{fonts}, {login => 'default', dashboard => 'default'}, 'old schema two receives font defaults');
ok(current()->{can_modify}, 'permission flag for administrator');
{
    local $CAN_MODIFY = 0;
    ok(!current()->{can_modify}, 'permission flag for read-only user');
}
for my $name (qw(index get_config update_config upload_asset upload apply)) {
    ok($METHODS{$name}->{protected}, "$name protected");
    my $privilege = $name eq 'index' || $name eq 'get_config' ? 'Sys.Audit' : 'Sys.Modify';
    is_deeply($METHODS{$name}->{permissions}->{check}, ['perm', '/', [$privilege]], "$name native permission");
}
for my $name (qw(update_config upload_asset upload apply)) {
    ok(!$METHODS{$name}->{parameters}->{properties}->{expected_revision}->{optional}, "$name requires revision");
}
{
    local $USER = 'admin@pam!token';
    for my $name (qw(index get_config update_config upload_asset upload apply)) {
        like(error_from(sub { call_api($name) }), qr/interactive Proxmox login/, "$name rejects API tokens");
    }
}
{
    local $USER = '';
    like(error_from(sub { current() }), qr/interactive Proxmox login/, 'anonymous rejected');
}
my $legacy = {%$initial, schema_version => 1}; delete($legacy->{update_safe}); delete($legacy->{fonts});
write_bytes("$root/etc/config.json", $JSON->encode($legacy));
is(current()->{config}->{schema_version}, 2, 'legacy config normalizes to schema two');
ok(current()->{config}->{update_safe}, 'legacy config enables update safety');
is($JSON->decode(read_bytes("$root/etc/config.json"))->{schema_version}, 1, 'read migration leaves stored bytes intact');
like(error_from(sub { apply_config($legacy, current()->{revision}) }), qr/unsupported schema_version/, 'mutations require schema two');
for my $url ('javascript:alert(1)', 'http://example.org/', 'https://user:pass@example.org/', 'https://example.org:0/', 'https://example.org:65536/', 'https://example.org:banana/', 'https://example.org/\\evil', "https://example.org/\n") {
    my $bad = PVE::API2::SLLCustoms::clone_default(); $bad->{website_url} = $url;
    like(error_from(sub { apply_config($bad, current()->{revision}) }), qr/website_url/, "unsafe URL rejected: " . substr($url, 0, 16));
}
my $unknown = PVE::API2::SLLCustoms::clone_default(); $unknown->{shell} = 'id';
like(error_from(sub { apply_config($unknown, current()->{revision}) }), qr/unknown configuration field/, 'unknown configuration rejected');
my $bad_bool = PVE::API2::SLLCustoms::clone_default(); $bad_bool->{update_safe} = 'yes';
like(error_from(sub { apply_config($bad_bool, current()->{revision}) }), qr/update_safe must/, 'invalid update-safe value rejected');
for my $value ('2', JSON::PP::true) {
    my $bad_schema = PVE::API2::SLLCustoms::clone_default(); $bad_schema->{schema_version} = $value;
    like(error_from(sub { apply_config($bad_schema, current()->{revision}) }), qr/unsupported schema_version/, 'schema version must be a JSON integer');
}
my $float_schema = $JSON->encode(PVE::API2::SLLCustoms::clone_default());
$float_schema =~ s/"schema_version":2/"schema_version":2.0/;
like(error_from(sub { call_api('update_config', {config_json => $float_schema, expected_revision => current()->{revision}}) }), qr/unsupported schema_version/, 'floating JSON schema rejected');
for my $value (0, 1, 'false') {
    my $bad_boolean = PVE::API2::SLLCustoms::clone_default(); $bad_boolean->{update_safe} = $value;
    like(error_from(sub { apply_config($bad_boolean, current()->{revision}) }), qr/update_safe must/, 'update-safe must be a JSON boolean');
}
is(PVE::API2::SLLCustoms::validate_url('HTTPS://example.org:443/'), 'https://example.org:443/', 'HTTPS scheme normalized');
my $config = PVE::API2::SLLCustoms::clone_default(); $config->{company_name} = 'Public Test';
$config->{fonts} = {login => 'dm-sans', dashboard => 'oxanium'};
my $before = current();
my $after = apply_config($config, $before->{revision});
is($after->{config}->{company_name}, 'Public Test', 'configuration applied');
is_deeply(current()->{config}->{fonts}, {login => 'dm-sans', dashboard => 'oxanium'}, 'separate font choices persist through Apply and reload');
isnt($after->{revision}, $before->{revision}, 'revision changes');
my $hashes = canonical_snapshot();
my $calls = $HELPER_CALLS;
like(error_from(sub { apply_config($initial, $before->{revision}) }), qr/409.*changed since/, 'stale revision conflicts');
is(canonical_snapshot(), $hashes, 'conflict leaves all canonical files unchanged');
is($HELPER_CALLS, $calls, 'conflict never invokes helper');
like(error_from(sub { apply_config($initial, undef) }), qr/expected_revision/, 'revision required at implementation boundary');

my $new_png = make_png("\x11\x22\x33\xff");
my $broken_png = make_png("\0\0\0\xff", 1);
my $decode_before = $DECODE_CALLS;
like(error_from(sub { apply_config($config, current()->{revision}, logo_base64 => encode_base64($broken_png, '')) }), qr/pixel decode failed/, 'CRC-valid but undecodable PNG rejected');
ok($DECODE_CALLS > $decode_before, 'uploads invoke pixel decoder');
is(canonical_snapshot(), $hashes, 'pixel failure leaves canonical files unchanged');
like(error_from(sub { apply_config($config, current()->{revision}, logo_base64 => encode_base64($new_png . 'trailing', '')) }), qr/trailing data/, 'trailing PNG bytes rejected');
my $bad_crc = $new_png; substr($bad_crc, 29, 1) = chr(ord(substr($bad_crc, 29, 1)) ^ 1);
like(error_from(sub { apply_config($config, current()->{revision}, logo_base64 => encode_base64($bad_crc, '')) }), qr/CRC/, 'bad PNG CRC rejected');
like(error_from(sub { call_api('upload_asset', {kind => '../../etc/passwd', content_base64 => encode_base64($new_png, ''), expected_revision => current()->{revision}}) }), qr/unsupported asset kind/, 'asset traversal rejected');
like(error_from(sub { PVE::API2::SLLCustoms::png_metadata('<svg>' . (' ' x 100), 'logo') }), qr/not a PNG/, 'SVG rejected');
my $upload = call_api('upload_asset', {kind => 'logo', content_base64 => encode_base64($new_png, ''), expected_revision => current()->{revision}});
is($upload->{assets}->{logo}->{sha256}, sha256_hex($new_png), 'valid decoded PNG applied');

# Exercise native-limit-friendly staging separately from the final canonical apply.
sub upload_request {
    my ($data, $kind, $revision, $index, $total, $id) = @_;
    my %param = (kind => $kind, expected_revision => $revision, index => $index,
        total_size => $total, content_base64 => encode_base64($data, ''));
    $param{upload_id} = $id if defined($id);
    cmp_ok(length($JSON->encode(\%param)), '<', 512 * 1024, 'chunk JSON body stays below native 512 KiB limit');
    return call_api('upload', \%param);
}
sub stage_png {
    my ($data, $kind, $revision) = @_;
    my ($id, $result);
    for (my $offset = 0, my $index = 0; $offset < length($data); $offset += 192 * 1024, $index++) {
        $result = upload_request(substr($data, $offset, 192 * 1024), $kind, $revision, $index, length($data), $id);
        $id = $result->{upload_id};
    }
    return $result;
}
sub clear_uploads {
    return if !-d "$root/state/uploads";
    opendir(my $dh, "$root/state/uploads") or die $!;
    my @ids = grep { /\A[0-9a-f]{32}\z/ } readdir($dh); closedir($dh);
    PVE::API2::SLLCustoms::remove_upload($_) for @ids;
}
my $large_png = $ENV{MAKEOVER_TEST_REAL_HELPER}
    ? read_bytes(dirname(__FILE__) . '/../assets/SLS_Proxmox.png')
    : substr($new_png, 0, length($new_png) - 12) . chunk('ruSt', 'x' x 1240000) . chunk('IEND', '');
cmp_ok(length($large_png), '>', 512 * 1024, 'roundtrip PNG exceeds native request limit');
my $stage_revision = current()->{revision};
my $stage_snapshot = canonical_snapshot();
my $first = upload_request(substr($large_png, 0, 192 * 1024), 'logo', $stage_revision, 0, length($large_png));
like($first->{upload_id}, qr/\A[0-9a-f]{32}\z/, 'server creates cryptographic-format upload identifier');
ok(!$first->{complete}, 'first chunk remains incomplete');
is($first->{next_index}, 1, 'next index is ordered');
is($first->{received}, 192 * 1024, 'received bytes tracked');
is(canonical_snapshot(), $stage_snapshot, 'staging leaves every canonical file unchanged');
my $stage_id = $first->{upload_id};
is((stat("$root/state/uploads/$stage_id"))[2] & 0777, 0700, 'upload directory private');
is((stat("$root/state/uploads/$stage_id/data.png"))[2] & 0777, 0600, 'staged bytes private');
{
    local $USER = 'other@pam';
    like(error_from(sub { upload_request('x', 'logo', $stage_revision, 1, length($large_png), $stage_id) }), qr/binding mismatch/, 'chunk upload bound to interactive user');
}
like(error_from(sub { upload_request('x', 'favicon', $stage_revision, 1, length($large_png), $stage_id) }), qr/binding mismatch/, 'chunk upload bound to artwork kind');
like(error_from(sub { upload_request('x', 'logo', '0' x 64, 1, length($large_png), $stage_id) }), qr/binding mismatch/, 'chunk upload bound to revision');
like(error_from(sub { upload_request('x', 'logo', $stage_revision, 1, length($large_png) + 1, $stage_id) }), qr/binding mismatch/, 'chunk upload bound to total size');
like(error_from(sub { upload_request('x', 'logo', $stage_revision, 0, length($large_png), $stage_id) }), qr/arrive in order/, 'replayed chunk rejected');
like(error_from(sub { upload_request('x', 'logo', $stage_revision, 1, 500, '../etc/passwd') }), qr/invalid upload_id/, 'staging traversal token rejected');
like(error_from(sub { upload_request('x', 'logo', $stage_revision, 1, 500) }), qr/start at index 0/, 'new session cannot start mid-stream');
like(error_from(sub { call_api('upload', {kind => 'logo', expected_revision => $stage_revision, index => 0, total_size => 3145729, content_base64 => 'eA=='}) }), qr/total_size/, 'staged total size bounded at three MiB');
like(error_from(sub { call_api('upload', {kind => 'logo', expected_revision => $stage_revision, index => 32, total_size => 500, content_base64 => 'eA=='}) }), qr/index/, 'chunk index bounded');
like(error_from(sub { call_api('upload', {kind => 'logo', expected_revision => $stage_revision, index => 0, total_size => 3145728, content_base64 => encode_base64('x' x (192 * 1024 + 1), '')}) }), qr/base64|192 KiB/, 'oversized chunk rejected');
like(error_from(sub { call_api('upload', {kind => 'logo', expected_revision => $stage_revision, index => 0, total_size => 500, content_base64 => 'AB=='}) }), qr/canonical.*base64/, 'noncanonical base64 rejected');
like(error_from(sub { apply_config($config, $stage_revision, logo_upload_id => $stage_id) }), qr/not complete/, 'incomplete upload cannot be applied');
my $staged;
for (my $offset = 192 * 1024, my $index = 1; $offset < length($large_png); $offset += 192 * 1024, $index++) {
    $staged = upload_request(substr($large_png, $offset, 192 * 1024), 'logo', $stage_revision, $index, length($large_png), $stage_id);
}
ok($staged->{complete}, 'final chunk fully validates large PNG');
is($staged->{upload_id}, $stage_id, 'session identifier remains stable');
is($staged->{received}, length($large_png), 'final size matches declaration');
is(canonical_snapshot(), $stage_snapshot, 'complete staging still leaves canonical files unchanged');
like(error_from(sub { apply_config($config, $stage_revision, favicon_upload_id => $stage_id) }), qr/binding mismatch/, 'apply token bound to kind');
{
    local $USER = 'other@pam';
    like(error_from(sub { apply_config($config, $stage_revision, logo_upload_id => $stage_id) }), qr/binding mismatch/, 'apply token bound to user');
}
write_bytes("$root/state/uploads/$stage_id/data.png", $large_png . 'x');
like(error_from(sub { apply_config($config, $stage_revision, logo_upload_id => $stage_id) }), qr/integrity mismatch/, 'staged file integrity rechecked at apply');
write_bytes("$root/state/uploads/$stage_id/data.png", $large_png);
{
    local $HELPER_FAILURES = 1;
    like(error_from(sub { apply_config($config, $stage_revision, logo_upload_id => $stage_id) }), qr/activation failure/, 'staged asset failure reports rollback');
    is(canonical_snapshot(), $stage_snapshot, 'staged asset transaction failure restores canonical files');
    ok(-d "$root/state/uploads/$stage_id", 'failed apply preserves stage for retry');
}
my $large_applied = apply_config($config, $stage_revision, logo_upload_id => $stage_id);
is($large_applied->{assets}->{logo}->{sha256}, sha256_hex($large_png), 'large PNG chunk roundtrip applies exact bytes');
ok(!-e "$root/state/uploads/$stage_id", 'successful commit consumes staged upload');
like(error_from(sub { apply_config($config, current()->{revision}, logo_upload_id => $stage_id) }), qr/unavailable/, 'consumed token cannot be reused');
like(error_from(sub { apply_config($config, current()->{revision}, logo_upload_id => '1' x 32, logo_base64 => encode_base64($new_png, '')) }), qr/not both/, 'ambiguous inline and staged source rejected');
like(error_from(sub { apply_config($config, current()->{revision}, logo_base64 => 'A' x 131072) }), qr/inline artwork request is too large/, 'combined inline request has conservative wire budget');

clear_uploads();
my $invalid_first = upload_request(substr($broken_png, 0, 40), 'logo', current()->{revision}, 0, length($broken_png));
my $invalid_id = $invalid_first->{upload_id};
my $invalid_before = canonical_snapshot();
like(error_from(sub { upload_request(substr($broken_png, 40), 'logo', current()->{revision}, 1, length($broken_png), $invalid_id) }), qr/pixel decode failed/, 'CRC-valid malformed final staged PNG rejected');
is(canonical_snapshot(), $invalid_before, 'invalid final PNG never touches canonical files');
is(length(read_bytes("$root/state/uploads/$invalid_id/data.png")), 40, 'invalid final bytes are not committed to staging');
clear_uploads();
my $stale = upload_request('x', 'logo', current()->{revision}, 0, 500);
my $stale_revision = current()->{revision};
my $change_revision = PVE::API2::SLLCustoms::clone_default(); $change_revision->{company_name} = 'Revision changed';
apply_config($change_revision, $stale_revision);
like(error_from(sub { upload_request('y', 'logo', $stale_revision, 1, 500, $stale->{upload_id}) }), qr/409.*changed since upload/, 'stale upload revision conflicts before accepting more bytes');
like(error_from(sub { apply_config($config, current()->{revision}, logo_upload_id => $stale->{upload_id}) }), qr/binding mismatch/, 'old upload cannot be rebound to new revision');
clear_uploads();
my @quota_ids;
for (1 .. 8) { push @quota_ids, upload_request('x', 'logo', current()->{revision}, 0, 500)->{upload_id}; }
like(error_from(sub { upload_request('x', 'logo', current()->{revision}, 0, 500) }), qr/quota reached \(8 sessions\)/, 'session quota is enforced');
{
    no warnings 'redefine';
    my $future = PVE::API2::SLLCustoms::upload_now() + 3601;
    local *PVE::API2::SLLCustoms::upload_now = sub { $future };
    my $after_expiry = upload_request('x', 'logo', current()->{revision}, 0, 500);
    ok(!grep({ -e "$root/state/uploads/$_" } @quota_ids), 'expired own-namespace sessions removed after one hour');
    ok(-d "$root/state/uploads/$after_expiry->{upload_id}", 'expired quota space can be reused');
}
clear_uploads();
my $byte_quota = upload_request('x', 'logo', current()->{revision}, 0, 500)->{upload_id};
# Simulate private orphan bytes from an interrupted old staging write. The
# quota counts real allocated file sizes rather than trusting JSON metadata.
write_bytes("$root/state/uploads/$byte_quota/data.png", 'x' x (33 * 1024 * 1024));
like(error_from(sub { upload_request('x', 'logo', current()->{revision}, 0, 500) }), qr/byte quota reached/, 'global byte quota counts real files');
write_bytes("$root/state/uploads/$byte_quota/data.png", 'x');
my $real_stage_file = "$root/state/uploads/$byte_quota/data.png";
unlink($real_stage_file); symlink("$root/etc/config.json", $real_stage_file) or die $!;
like(error_from(sub { upload_request('x', 'logo', current()->{revision}, 0, 500) }), qr/refusing symlink/, 'symlinked staged data rejected without following it');
unlink($real_stage_file); write_bytes($real_stage_file, 'x'); chmod(0600, $real_stage_file);
clear_uploads();

# Inject failures at transaction boundaries, leaving backup and filesystem code real.
my $real_atomic = \&PVE::API2::SLLCustoms::atomic_write;
my $real_audit = \&PVE::API2::SLLCustoms::audit_event;
my $real_payload = \&PVE::API2::SLLCustoms::state_payload;
my $changed = PVE::API2::SLLCustoms::clone_default(); $changed->{company_name} = 'Must Roll Back';
{
    no warnings 'redefine';
    my $failed = 0;
    local *PVE::API2::SLLCustoms::atomic_write = sub {
        die "simulated disk failure\n" if $_[0] eq "$root/assets/SLS_Proxmox_Favicon.png" && !$failed++;
        return $real_atomic->(@_);
    };
    my $snapshot = canonical_snapshot();
    like(error_from(sub { apply_config($changed, current()->{revision}, favicon_base64 => encode_base64($new_png, '')) }), qr/Previous configuration and artwork restored/, 'disk failure reports successful rollback');
    is(canonical_snapshot(), $snapshot, 'disk failure after config write restores all files');
}
{
    local $HELPER_FAILURES = 1;
    my $snapshot = canonical_snapshot();
    like(error_from(sub { apply_config($changed, current()->{revision}) }), qr/simulated activation failure/, 'helper failure reported');
    is(canonical_snapshot(), $snapshot, 'helper failure restores all files');
}
{
    no warnings 'redefine';
    my $failed = 0;
    local *PVE::API2::SLLCustoms::audit_event = sub { die "simulated audit disk failure\n" if !$failed++; return $real_audit->(@_); };
    my $snapshot = canonical_snapshot();
    like(error_from(sub { apply_config($changed, current()->{revision}) }), qr/simulated audit disk failure/, 'audit failure reported');
    is(canonical_snapshot(), $snapshot, 'audit failure restores all files and presentation');
}
{
    no warnings 'redefine';
    my $read_count = 0;
    local *PVE::API2::SLLCustoms::state_payload = sub { die "simulated post-write state failure\n" if ++$read_count == 3; return $real_payload->(@_); };
    my $snapshot = canonical_snapshot();
    like(error_from(sub { apply_config($changed, current()->{revision}) }), qr/post-write state failure/, 'post-write state failure reported');
    is(canonical_snapshot(), $snapshot, 'post-write state failure rolls back');
}
{
    no warnings 'redefine';
    local *PVE::API2::SLLCustoms::atomic_write = sub {
        die "persistent disk failure\n" if $_[0] eq "$root/assets/SLS_Proxmox.png";
        return $real_atomic->(@_);
    };
    my $snapshot = canonical_snapshot();
    my $error = error_from(sub { apply_config($changed, current()->{revision}, logo_base64 => encode_base64($logo, '')) });
    like($error, qr/Rollback requires operator review:.*logo restore/s, 'rollback write failures explicitly reported');
    like($error, qr/Recovery backup:/, 'rollback failure identifies recovery backup');
    is(canonical_snapshot(), $snapshot, 'other snapshot files restored despite one rollback error');
}
{
    local $HELPER_FAILURES = 2;
    like(error_from(sub { apply_config($changed, current()->{revision}) }), qr/Rollback requires operator review:.*presentation reapply/s, 'rollback helper failure explicitly reported');
}
my $maintenance_revision = current()->{revision};
my $maintenance_snapshot = canonical_snapshot();
write_bytes("$root/run/makeover.maintenance", "Lifecycle active\n"); chmod(0600, "$root/run/makeover.maintenance");
like(error_from(sub { current() }), qr/503.*being updated/, 'maintenance blocks API reads under shared lock');
like(error_from(sub { apply_config($changed, $maintenance_revision) }), qr/503.*being updated/, 'maintenance blocks mutations under shared lock');
is(canonical_snapshot(), $maintenance_snapshot, 'maintenance leaves canonical data untouched');
chmod(0644, "$root/run/makeover.maintenance");
like(error_from(sub { current() }), qr/unsafe.*maintenance marker/, 'unsafe maintenance marker permissions fail closed');
unlink("$root/run/makeover.maintenance");
symlink("$root/etc/config.json", "$root/run/makeover.maintenance") or die $!;
like(error_from(sub { current() }), qr/refusing symlink/, 'symlinked maintenance marker rejected');
unlink("$root/run/makeover.maintenance");
my $lock_path = "$root/run/makeover.lock";
unlink($lock_path); symlink("$root/etc/config.json", $lock_path) or die $!;
like(error_from(sub { current() }), qr/refusing symlink/, 'symlinked lock rejected');
unlink($lock_path);
rename("$root/bin/helper", "$root/bin/helper-original") or die $!;
symlink("$root/bin/helper-original", "$root/bin/helper") or die $!;
like(error_from(sub { PVE::API2::SLLCustoms::checked_helper() }), qr/refusing symlink/, 'symlinked helper rejected');
unlink("$root/bin/helper"); rename("$root/bin/helper-original", "$root/bin/helper") or die $!;
rename("$root/state", "$root/state-original") or die $!;
symlink("$root/state-original", "$root/state") or die $!;
like(error_from(sub { PVE::API2::SLLCustoms::ensure_state() }), qr/refusing symlink/, 'symlinked state directory rejected');
unlink("$root/state"); rename("$root/state-original", "$root/state") or die $!;

# Both writers start with the same revision. Exactly one may commit.
my $race_revision = current()->{revision};
pipe(my $start_read, my $start_write) or die $!;
my @children;
for my $name ('Race A', 'Race B') {
    my $pid = fork(); die "fork failed: $!" if !defined($pid);
    if (!$pid) {
        close($start_write); read($start_read, my $go, 1); close($start_read);
        my $race_config = PVE::API2::SLLCustoms::clone_default(); $race_config->{company_name} = $name;
        my $error = error_from(sub { apply_config($race_config, $race_revision) });
        POSIX::_exit(!$error ? 0 : $error =~ /409.*changed since/ ? 2 : 3);
    }
    push @children, $pid;
}
close($start_read); print {$start_write} 'xx'; close($start_write);
my @statuses;
for my $pid (@children) { waitpid($pid, 0); push @statuses, $? >> 8; }
is_deeply([sort @statuses], [0, 2], 'shared lock and revision permit exactly one concurrent writer');
like(current()->{config}->{company_name}, qr/\ARace [AB]\z/, 'concurrent apply leaves one coherent winner');
for (1 .. 24) { apply_config($config, current()->{revision}); }
opendir(my $backup_dh, "$root/state/backups") or die $!;
my @sets = grep { /\A\d{8}T\d{6}Z-/ } readdir($backup_dh); closedir($backup_dh);
is(scalar(@sets), 20, 'backup history capped at twenty complete sets');
for my $set (@sets) { ok(-f "$root/state/backups/$set/manifest.json", 'retained backup set has recovery manifest'); }
for (1 .. 5) {
    write_bytes("$root/state/audit.jsonl", ' ' x (1024 * 1024 - 2));
    PVE::API2::SLLCustoms::audit_event('root@pam', 'test-rotation', {});
}
ok(-f "$root/state/audit.jsonl.3" && !-e "$root/state/audit.jsonl.4", 'audit capped at three historical files');
cmp_ok(-s "$root/state/audit.jsonl", '<=', 1024 * 1024, 'active audit remains bounded');
is((stat("$root/etc/config.json"))[2] & 0777, 0600, 'canonical configuration private');
is((stat("$root/state/audit.jsonl"))[2] & 0777, 0600, 'audit private');
is((stat("$root/state"))[2] & 0777, 0700, 'state directory private');
# Exercise the actual protected-page implementation with fake ticket verification.
$INC{'PVE/API2/SLLCustoms.pm'} = 1;
{
    local $ENV{SLL_MAKEOVER_SERVICE} = 'test';
    my ($bootstrap_path) = abs_path(dirname(__FILE__) . '/../SLL/Makeover/Bootstrap.pm') =~ /\A(\/[A-Za-z0-9_.\/-]+)\z/;
    my $bootstrap = do($bootstrap_path);
    die "isolated bootstrap failed: $@ $!" if !$bootstrap;
}
my $server = {cookie_name => 'PVEAuthCookie'};
my $anonymous = SLL::Makeover::Bootstrap::protected_page($server, HTTP::Request->new('GET', '/SLL-Customs'));
is($anonymous->code, 401, 'protected page rejects anonymous requests');
like($anonymous->content, qr/Proxmox login required/, 'anonymous denial explains native login requirement');
is($anonymous->header('Content-Security-Policy'), "default-src 'none'; frame-ancestors 'none'", 'anonymous denial CSP');
is($anonymous->header('X-Frame-Options'), 'DENY', 'anonymous denial prohibits framing');
is($anonymous->header('X-Content-Type-Options'), 'nosniff', 'anonymous denial nosniff');
is($anonymous->header('Referrer-Policy'), 'no-referrer', 'anonymous denial suppresses referrer');
like($anonymous->header('Cache-Control'), qr/no-store/, 'anonymous denial is not cached');
my $bad_request = HTTP::Request->new('GET', '/SLL-Customs'); $bad_request->header('Cookie' => 'PVEAuthCookie=invalid-ticket');
is(SLL::Makeover::Bootstrap::protected_page($server, $bad_request)->code, 401, 'invalid ticket rejected');
for my $ticket ('new-tfa-ticket', 'old-tfa-ticket', 'u2f-ticket') {
    my $half = HTTP::Request->new('GET', '/SLL-Customs'); $half->header('Cookie' => 'PVEAuthCookie=' . $ticket);
    is(SLL::Makeover::Bootstrap::protected_page($server, $half)->code, 401, "incomplete $ticket rejected");
}
my $disabled = HTTP::Request->new('GET', '/SLL-Customs'); $disabled->header('Cookie' => 'PVEAuthCookie=valid-ticket');
{ local $ENABLED_PAGE_USER = 0; is(SLL::Makeover::Bootstrap::protected_page($server, $disabled)->code, 401, 'disabled native account rejected'); }
my $good_request = HTTP::Request->new('GET', '/SLL-Customs'); $good_request->header('Cookie' => 'PVEAuthCookie=valid-ticket');
my $authenticated = SLL::Makeover::Bootstrap::protected_page($server, $good_request);
is($authenticated->code, 303, 'valid native ticket redirects');
is($authenticated->header('Location'), '/?sll-customs=1', 'authenticated redirect opens settings through SPA');
like($authenticated->header('Cache-Control'), qr/no-store/, 'authenticated redirect is not cached');
done_testing();
