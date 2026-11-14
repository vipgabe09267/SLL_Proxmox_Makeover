#!/usr/bin/perl
# PVE-only regression: actual native HTTP parser, auth gate, protected forwarding,
# CSRF exposure, real WebAuthn crypto and memory-only native signing keys.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use File::Basename qw(dirname);
use Cwd qw(abs_path);
use IO::Socket::INET;
use IO::Handle;
use IPC::Open2 qw(open2);
use JSON::PP;
use LWP::UserAgent;
use HTTP::Request;
use POSIX qw(_exit);
use Fcntl qw(:flock O_RDWR O_CREAT O_NOFOLLOW);
BEGIN {
    if ($> != 0 || !eval { require PVE::HTTPServer; require Crypt::OpenSSL::RSA; 1 }) {
        plan skip_all => 'Requires root and the installed native Proxmox Perl HTTP runtime.';
    }
}
use PVE::API2;
use PVE::APIServer::Formatter::Standard;
use PVE::AccessControl;
use PVE::Auth::PVE;
use PVE::Cluster;
use PVE::RPCEnvironment;
use PVE::Ticket;
use PVE::Tools;

{ package SLLTestNativeTFA;
    sub api_list_user_tfa { return $_[0]->{users}->{$_[1]} // []; }
    sub write { JSON::PP->new->canonical->encode({users => $_[0]->{users}}) }
    sub api_update_tfa_entry {
        my ($self, $user, $id, $description, $enable) = @_;
        my @entry = grep { $_->{id} eq $id } @{$self->{users}->{$user} // []};
        die "fixture native factor missing\n" if @entry != 1;
        $entry[0]->{enable} = $enable ? JSON::PP::true : JSON::PP::false;
    }
    sub api_delete_tfa {
        my ($self, $user, $id) = @_;
        die "fixture native factor missing\n" if !grep { $_->{id} eq $id } @{$self->{users}->{$user} // []};
        $self->{users}->{$user} = [grep { $_->{id} ne $id } @{$self->{users}->{$user}}];
        return scalar(@{$self->{users}->{$user}}) ? 1 : 0;
    }
}

$ENV{PATH} = '/usr/sbin:/usr/bin:/sbin:/bin';
delete @ENV{qw(IFS CDPATH ENV BASH_ENV HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy)};
# Explicit test dependency paths only. The production bridge uses Python -I.
my @python_paths;
for my $key (qw(PYTHONPATH LD_LIBRARY_PATH)) {
    next if !exists($ENV{$key});
    my @safe;
    for my $part (split(/:/, $ENV{$key})) {
        my ($path) = $part =~ m{\A(/[A-Za-z0-9_./-]+)\z};
        die "unsafe fixture dependency path\n" if !defined($path) || $path =~ m{(?:\A|/)\.\.(?:/|\z)};
        push @safe, $path;
    }
    $ENV{$key} = join(':', @safe);
    @python_paths = @safe if $key eq 'PYTHONPATH';
}
my ($source) = abs_path(dirname(__FILE__) . '/..') =~ m{\A(/[A-Za-z0-9_./-]+)\z};
my $json = JSON::PP->new->utf8->canonical;
my $private = tempdir('.sll-passkeys-http-XXXXXX', DIR => '/root', CLEANUP => 1);
my $public = tempdir('sll-passkeys-http-XXXXXX', TMPDIR => 1, CLEANUP => 1);
chmod(0755, $public) or die $!;
sub read_bytes { open(my $fh, '<', $_[0]) or die $!; local $/; return <$fh>; }
sub write_bytes { my ($path, $data, $mode) = @_; open(my $fh, '>', $path) or die $!; print {$fh} $data or die $!; close($fh) or die $!; chmod($mode // 0600, $path) or die $!; }
my $userfile = "$public/user.cfg";
my $userline = join(':', 'user', 'alice@pve', 1, 0, '', '', '', '', '') . ":\n";
write_bytes($userfile, $userline, 0644);
write_bytes("$public/password-record", '$6$fixture$' . ('A' x 86), 0644);
write_bytes("$public/native-tfa.json", $json->encode({users => {
    'alice@pve' => [map { {id => $_->[0], type => $_->[1], description => 'Offline fixture', enable => JSON::PP::true} }
        ['own-native-key', 'webauthn'], ['own-u2f-key', 'u2f'], ['totp-key', 'totp'], ['recovery-key', 'recovery']],
    'other@pve' => [{id => 'other-native-key', type => 'webauthn'}],
}}), 0644);
my $core = read_bytes("$source/scripts/passkeys.py");
$core =~ s{\Q/var/lib/proxmox-makeover/passkeys\E}{$private/state}g;
$core =~ s/import sys\n/"import sys\nsys.path[:0] = " . $json->encode(\@python_paths) . "\n"/e;
write_bytes("$private/passkeys.py", $core, 0600);
my $module = read_bytes("$source/PVE/API2/SLLPasskeys.pm");
$module =~ s{\Q/usr/local/libexec/proxmox-makeover/passkeys.py\E}{$private/passkeys.py}g;
$module =~ s{\Q/var/lib/proxmox-makeover/control.lock\E}{$private/control.lock}g;
$module =~ s{\Q/var/lib/proxmox-makeover/maintenance.json\E}{$private/maintenance}g;
my ($isolated_module) = $module =~ /\A([\s\S]*)\z/;
my $loaded = eval $isolated_module; die $@ if !$loaded;
$INC{'PVE/API2/SLLPasskeys.pm'} = __FILE__;
PVE::API2->register_method({subclass => 'PVE::API2::SLLPasskeys', path => 'sll-passkeys'});
PVE::API2::SLLPasskeys::install_auth_hook();

# Exercise the installed PVE password plugin's actual hash policy, including
# transparent upgrades when supported. CFS operations are redirected to private
# in-memory fixture records before any authentication function is invoked.
sub native_password_compatibility {
    pipe(my $reader, my $writer) or die $!;
    my $pid = fork(); die $! if !defined($pid);
    if (!$pid) {
        close($reader);
        my $result = eval {
            my $native_authenticate = \&PVE::Auth::PVE::authenticate_user;
            my ($memory, $scenario, $calls, $writes);
            my $password = 'isolated-current-password';
            my $reset_hash = crypt('different-reset-password', '$6$isolatedreset$');
            my $renewed_hash = crypt($password, '$6$isolatedrenewal$');
            die "fixture crypt unavailable\n" if $reset_hash !~ /^\$6\$/ || $renewed_hash !~ /^\$6\$/;
            {
                no warnings qw(redefine once);
                *PVE::API2::SLLPasskeys::local_user = sub {
                    die "fixture rejected account\n" if $_[0] ne 'alice@pve';
                    return ('alice@pve', 'alice', 'pve', {type => 'pve'});
                };
                *PVE::Auth::Plugin::lookup = sub { return 'PVE::Auth::PVE'; };
                *PVE::Cluster::cfs_update = sub { return 1; };
                *PVE::Cluster::check_cfs_quorum = sub { return 1; };
                my $read_shadow = sub {
                    die "fixture refused config read\n" if $_[0] ne 'priv/shadow.cfg'; return $memory;
                };
                *PVE::Cluster::cfs_read_file = $read_shadow;
                *PVE::Auth::PVE::cfs_read_file = $read_shadow;
                *PVE::Auth::PVE::cfs_write_file = sub {
                    die "fixture refused config write\n" if $_[0] ne 'priv/shadow.cfg';
                    $memory = $_[1]; $writes++; return;
                };
                *PVE::Auth::PVE::cfs_lock_file = sub {
                    die "fixture refused config lock\n" if $_[0] ne 'priv/shadow.cfg';
                    $_[2]->(); $@ = ''; return;
                };
                *PVE::Auth::PVE::authenticate_user = sub {
                    $calls++; $native_authenticate->(@_);
                    # Explicitly model two concurrent record changes for this
                    # race case, independently of upstream's upgrade policy.
                    $memory->{users}->{alice}->{shadow} = $renewed_hash
                        if $scenario eq 'twice' && $calls == 1;
                    $memory->{users}->{alice}->{shadow} = $reset_hash
                        if ($scenario eq 'reset' && $calls == 1) || ($scenario eq 'twice' && $calls == 2);
                    return 1;
                };
            }
            my %out;
            for my $case ('rehash', 'reset', 'twice') {
                $scenario = $case; $calls = 0; $writes = 0;
                my $legacy = crypt($password, '$6$isolatedlegacy$');
                die "fixture crypt unavailable\n" if $legacy !~ /^\$6\$/;
                $memory = {users => {alice => {shadow => $legacy}}};
                my $proof = eval { PVE::API2::SLLPasskeys::verify_primary_password('alice@pve', $password) };
                my $accepted = !$@ && ref($proof) eq 'HASH';
                $out{$case} = {accepted => $accepted ? 1 : 0, calls => $calls, writes => $writes};
                $out{$case}->{current_binding} = $accepted && PVE::API2::SLLPasskeys::same_binding(
                    $proof->{binding}, PVE::API2::SLLPasskeys::account_binding('alice@pve')) ? 1 : 0;
                $out{$case}->{upgraded} = $memory->{users}->{alice}->{shadow} ne $legacy ? 1 : 0;
            }
            return \%out;
        };
        $result = {fixture_error => 1} if !$result || $@;
        print {$writer} $json->encode($result); close($writer);
        _exit(0);
    }
    close($writer);
    my $encoded = do { local $/; <$reader> }; close($reader); waitpid($pid, 0);
    return eval { $json->decode($encoded) } // {};
}
my $native_password = native_password_compatibility();
ok(!$native_password->{fixture_error} && $native_password->{rehash}, 'installed native password-plugin fixture is isolated and operational');
ok($native_password->{rehash}->{accepted} && $native_password->{rehash}->{current_binding},
    'actual native password policy enrolls only the freshly verified current generation');
my $native_upgrades = $native_password->{rehash}->{upgraded};
diag('Installed native PVE password policy: ' . ($native_upgrades ? 'transparent hash upgrade' : 'preserve existing hash'));
is($native_password->{rehash}->{calls}, $native_upgrades ? 2 : 1,
    'native password proof count follows the installed hash-upgrade policy');
ok($native_upgrades ? $native_password->{rehash}->{writes} >= 1 : $native_password->{rehash}->{writes} == 0,
    'only the installed upgrade policy writes the in-memory shadow fixture');
ok(!$native_password->{reset}->{accepted}, 'actual native plugin rejects an old password after a different-password reset');
is($native_password->{reset}->{calls}, 2, 'different-password reset is denied on the single native retry');
ok(!$native_password->{twice}->{accepted}, 'actual native second-generation race cannot enroll after the retry');
is($native_password->{twice}->{calls}, 2, 'a second race never triggers a third password verification');

my $rsa = Crypt::OpenSSL::RSA->generate_key(2048);
my $rsa_public = Crypt::OpenSSL::RSA->new_public_key($rsa->get_public_key_string());
my $csrf_secret = 'isolated-http-fixture-csrf-secret-' . $$;
my $key_time = time();
my $root_socket = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 16, ReuseAddr => 1) or die $!;
my $edge_socket = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0, Listen => 16, ReuseAddr => 1) or die $!;
my $root_port = $root_socket->sockport;
my $edge_port = $edge_socket->sockport;
my @children;
my $driver_pid;
my ($driver_out, $driver_in);
sub allowed_path {
    my ($path) = @_;
    return $path =~ m{\A/api2/(?:json|extjs)/(?:sll-passkeys/(?:status|mode|credentials(?:/[0-9a-f]{64})?|register-begin|register-finish|login-begin|login-finish|remove-second-factor)|access/ticket)\z};
}
sub start_server {
    my ($socket, $trusted) = @_;
    pipe(my $ready_read, my $ready_write) or die $!;
    my $pid = fork(); die $! if !defined($pid);
    if (!$pid) {
        close($ready_read);
        my $errorfile = "$public/" . ($trusted ? 'root' : 'edge') . '-errors.log';
        open(STDERR, '>>', $errorfile) or _exit(2);
        # Every authority, account/config read and signing key in this child is
        # fixture-only. No native service program is initialized or executed.
        no warnings qw(redefine prototype once);
        *PVE::Cluster::cfs_update = sub { return 1; };
        *PVE::Cluster::cfs_read_file = sub {
            my ($name) = @_;
            return {webauthn => {id => 'pve.example.test', origin => 'https://pve.example.test', rp => 'Example PVE'}} if $name eq 'datacenter.cfg';
            return {ids => {pve => {type => 'pve', (-e "$public/realm-tfa-required" ? (tfa => 'type=oath') : ())}, pam => {type => 'pam'}}} if $name eq 'domains.cfg';
            return {users => {alice => {shadow => read_bytes("$public/password-record")}}} if $name eq 'priv/shadow.cfg';
            return bless($json->decode(read_bytes("$public/native-tfa.json")), 'SLLTestNativeTFA') if $name eq 'priv/tfa.cfg';
            return PVE::AccessControl::parse_user_config($userfile, read_bytes($userfile)) if $name eq 'user.cfg';
            die "fixture refused native config read\n";
        };
        my $fixture_read = \&PVE::Cluster::cfs_read_file;
        for my $package (qw(PVE::AccessControl PVE::Auth::PVE PVE::Auth::Plugin PVE::API2::AccessControl PVE::API2::TFA)) {
            no strict 'refs'; *{"${package}::cfs_read_file"} = $fixture_read;
            *{"${package}::cfs_write_file"} = sub { die 'fixture refuses native configuration writes'; };
        }
        my $fixture_write = sub {
            if ($_[0] eq 'user.cfg' && ref($_[1]) eq 'HASH') {
                write_bytes($userfile, PVE::AccessControl::write_user_config($userfile, $_[1]), 0644);
                return;
            }
            die "fixture refused native writer\n" if $_[0] ne 'priv/tfa.cfg' || ref($_[1]) ne 'SLLTestNativeTFA';
            write_bytes("$public/native-tfa.json", $json->encode({users => $_[1]->{users}}), 0644);
            open(my $audit, '>>', "$public/native-tfa-writes") or die $!; print {$audit} "native-delete\n"; close($audit);
        };
        *PVE::Cluster::cfs_write_file = $fixture_write;
        *PVE::API2::TFA::cfs_write_file = $fixture_write;
        *PVE::AccessControl::cfs_write_file = $fixture_write;
        *PVE::AccessControl::parse_priv_tfa_config = sub {
            die "fixture refused native config parser\n" if $_[0] ne 'priv/tfa.cfg';
            return bless($json->decode($_[1]), 'SLLTestNativeTFA');
        };
        *PVE::AccessControl::cfs_lock_file = sub {
            die "fixture refused native lock\n" if $_[0] ne 'priv/tfa.cfg' && $_[0] ne 'user.cfg';
            my $name = $_[0] eq 'priv/tfa.cfg' ? 'native-tfa.lock' : 'native-user.lock';
            sysopen(my $lock, "$private/$name", O_RDWR | O_CREAT | O_NOFOLLOW, 0600) or die $!;
            flock($lock, LOCK_EX) or die $!;
            my $result = eval { $_[2]->() }; my $error = $@; close($lock); $@ = $error; return $result;
        };
        *PVE::Cluster::log_msg = sub {};
        *PVE::Cluster::get_clinfo = sub { return {cluster => {}}; };
        *PVE::AccessControl::get_privkey = sub { return $rsa; };
        *PVE::AccessControl::get_pubkey = sub { return ($rsa_public, $key_time); };
        *PVE::AccessControl::assemble_csrf_prevention_token = sub { PVE::Ticket::assemble_csrf_prevention_token($csrf_secret, $_[0]); };
        *PVE::AccessControl::verify_csrf_prevention_token = sub { PVE::Ticket::verify_csrf_prevention_token($csrf_secret, $_[0], $_[1], -300, 7200, $_[2]); };
        *PVE::AccessControl::verify_token = sub { die "fixture rejects all API tokens\n"; };
        my $original_authenticate = \&PVE::AccessControl::authenticate_user;
        *PVE::AccessControl::authenticate_user = sub { die "fixture rejects all other accounts\n" if $_[0] ne 'alice@pve'; return $original_authenticate->(@_); };
        *PVE::Auth::PVE::authenticate_user = sub { die "fixture password rejected\n" if $_[3] ne 'alice' || $_[4] ne 'fixture-password'; return 1; };
        *PVE::AccessControl::authenticate_2nd_new = sub {
            my ($user, $realm, $response, $challenge) = @_;
            die "fixture rejects other MFA accounts\n" if $user ne 'alice@pve' || $realm ne 'pve';
            if (defined($challenge)) {
                PVE::AccessControl::verify_ticket($challenge, 0, $user);
                die "fixture MFA rejected\n" if ($response // '') ne 'totp:fixture-code' && ($response // '') ne 'webauthn:fixture-native-proof';
                return undef;
            }
            my $native = $json->decode(read_bytes("$public/native-tfa.json"))->{users}->{'alice@pve'} // [];
            return '{"webauthn":true}' if grep { ($_->{type} // '') =~ /\A(?:webauthn|u2f)\z/ && (!exists($_->{enable}) || $_->{enable}) } @$native;
            return -e "$public/mfa-required" ? '{"totp":true}' : undef;
        };
        for my $package (qw(PVE::SafeSyslog PVE::HTTPServer PVE::APIServer::AnyEvent PVE::API2::AccessControl)) {
            no strict 'refs'; *{"${package}::syslog"} = sub {};
        }
        *PVE::INotify::inotify_init = sub {};
        *PVE::HTTPServer::initialize_cert_cache = sub {};
        my $original_init = \&PVE::RPCEnvironment::init_request;
        *PVE::RPCEnvironment::init_request = sub { my ($self) = @_; return $original_init->($self, userconfig => $userfile); };
        # This listener must never expose native host/guest administration. Fence
        # BEFORE dispatch, including requests with any valid fixture cookie.
        my $original_header = \&PVE::APIServer::AnyEvent::process_header;
        *PVE::APIServer::AnyEvent::process_header = sub {
            my ($self, $request_state) = @_;
            my $path = URI::Escape::uri_unescape($request_state->{request}->uri->path());
            if (!allowed_path($path)) { $self->error($request_state, 403, 'Fixture route unavailable'); return 0; }
            if ($path =~ m{/sll-passkeys/(?:remove-second-factor|mode)\z}) {
                die "password-bearing query reached native fixture\n" if defined($request_state->{request}->uri->query());
            }
            return $original_header->(@_);
        };
        # Native forwarding's target is fixed at localhost:85. Redirect that one
        # test-only target before opening a socket; no connection to port85 is
        # possible, and every other target is refused.
        my $native_http_request = \&PVE::APIServer::AnyEvent::http_request;
        *PVE::APIServer::AnyEvent::http_request = sub {
            my ($method, $target, @rest) = @_;
            die "fixture refused external proxy target\n" if $target !~ s{\Ahttp://localhost:85/}{http://127.0.0.1:$root_port/};
            return $native_http_request->($method, $target, @rest);
        };
        my $lockfile = "$public/" . ($trusted ? 'root' : 'edge') . '-accept.lock';
        open(my $lock, '>>', $lockfile) or die $!;
        my $server = PVE::HTTPServer->new(socket => $socket, lockfh => $lock, lockfile => $lockfile,
            trusted_env => $trusted, pages => {}, dirs => {}, compression => 0,
            max_requests => 1000, keep_alive => 0);
        if (!$trusted) {
            my $uid = getpwnam('www-data'); die "www-data fixture account missing\n" if !defined($uid);
            $> = $uid; die "cannot drop fixture euid\n" if $> == 0;
        }
        print {$ready_write} "ready\n"; close($ready_write);
        $server->run(); _exit(0);
    }
    close($ready_write);
    push @children, $pid;
    my $ready = <$ready_read>; close($ready_read);
    die "native fixture server did not start\n" if !defined($ready) || $ready ne "ready\n";
}
my $ua = LWP::UserAgent->new(timeout => 15, keep_alive => 0);
$ua->proxy(['http', 'https'], undef);
my $base = "http://127.0.0.1:$edge_port/api2/json";
sub http_call {
    my ($method, $path, $body, $token, $ticket, $extra) = @_;
    my $request = HTTP::Request->new($method, $base . $path);
    $request->header(Accept => 'application/json');
    $request->header(CSRFPreventionToken => $token) if defined($token);
    $request->header(Cookie => 'PVEAuthCookie=' . $ticket) if defined($ticket);
    $request->header(%$extra) if $extra;
    if (defined($body)) { $request->header('Content-Type' => 'application/json'); $request->content($json->encode($body)); }
    my $response = $ua->request($request);
    my $parsed = eval { $json->decode($response->decoded_content) };
    return ($response, ref($parsed) eq 'HASH' ? $parsed->{data} : undef);
}
my $driver_id = 0;
sub proof {
    my ($op, $begin, $params) = @_;
    my $id = ++$driver_id;
    print {$driver_in} $json->encode({id => $id, op => $op, begin => $begin, params => $params // {}}), "\n";
    my $line = <$driver_out>; die "authenticator fixture stopped\n" if !defined($line);
    my $result = $json->decode($line);
    die "authenticator fixture rejected request\n" if $result->{error} || $result->{id} != $id;
    return $result->{response};
}
my $cookie = PVE::Ticket::assemble_rsa_ticket($rsa, 'PVE', 'alice@pve');
my $csrf = PVE::Ticket::assemble_csrf_prevention_token($csrf_secret, 'alice@pve');
my $ok = eval {
    start_server($root_socket, 1);
    start_server($edge_socket, 0);
    close($root_socket); close($edge_socket);
    $driver_pid = open2($driver_out, $driver_in, '/usr/bin/python3', '-u', "$source/tests/passkeys-crypto-fixture.py");
    $driver_in->autoflush(1);
    my ($status_response, $status) = http_call('GET', '/sll-passkeys/status');
    is($status_response->code, 200, 'public status traverses native unprivileged proxy and privileged API');
    ok($status && $status->{primary_passkeys} && $status->{supported}, 'real isolated Python core is available');
    ok($status->{secondary_removal}, 'actual resident status advertises the protected secondary-removal bridge');
    ok($status->{per_user_mode}, 'actual resident status advertises authoritative per-user passkey mode');
    my $secondary_path = '/sll-passkeys/remove-second-factor';
    my $secondary_body = {id => 'own-native-key', password => 'fixture-password'};
    my ($anonymous_secondary) = http_call('POST', $secondary_path, $secondary_body);
    is($anonymous_secondary->code, 401, 'secondary-removal POST is not a public login endpoint');
    my ($csrf_secondary) = http_call('POST', $secondary_path, $secondary_body, undef, $cookie);
    is($csrf_secondary->code, 401, 'native edge CSRF protects body-only secondary removal');
    my ($token_secondary) = http_call('POST', $secondary_path, $secondary_body, $csrf, undef,
        {Authorization => 'PVEAPIToken=alice@pve!test=never-real'});
    is($token_secondary->code, 401, 'secondary-removal bridge rejects API-token authorization');
    my ($foreign_user_secondary) = http_call('POST', $secondary_path, {%$secondary_body, userid => 'other@pve'}, $csrf, $cookie);
    is($foreign_user_secondary->code, 400, 'secondary-removal JSON never accepts a target account');
    for my $id ('other-native-key', 'totp-key', 'recovery-key') {
        my ($forbidden_secondary) = http_call('POST', $secondary_path, {id => $id, password => 'fixture-password'}, $csrf, $cookie);
        is($forbidden_secondary->code, 401, 'native HTTP rejects unowned or non-security-key secondary entries');
    }
    for my $password (undef, 'wrong-password') {
        my ($failed_secondary) = http_call('POST', $secondary_path, {id => 'own-native-key', defined($password) ? (password => $password) : ()}, $csrf, $cookie);
        is($failed_secondary->code, 401, 'actual native password reauthentication is required through the POST bridge');
        unlike($failed_secondary->decoded_content, qr/wrong-password|fixture-password|private.*diagnostic/, 'native reauthentication errors reveal no submitted secret');
    }
    my $disabled_secondary_line = $userline; $disabled_secondary_line =~ s/:1:0:/:0:0:/;
    write_bytes($userfile, $disabled_secondary_line, 0644);
    my ($disabled_secondary) = http_call('POST', $secondary_path, $secondary_body, $csrf, $cookie);
    is($disabled_secondary->code, 401, 'disabled native account cannot use secondary removal');
    write_bytes($userfile, $userline, 0644);
    ok(!-e "$public/native-tfa-writes", 'all failed native secondary removals left the isolated writer untouched');
    my ($secondary_response, $secondary_result) = http_call('POST', $secondary_path, $secondary_body, $csrf, $cookie);
    is($secondary_response->code, 200, 'actual native deletion accepts the nonroot password in the protected POST JSON body');
    ok(ref($secondary_result) eq 'HASH' && $secondary_result->{removed}, 'secondary-removal success is the advertised object');
    my $native_after = $json->decode(read_bytes("$public/native-tfa.json"));
    ok(!grep({ $_->{id} eq 'own-native-key' } @{$native_after->{users}->{'alice@pve'}}), 'actual native API writer removed only the requested own security key');
    is(scalar(@{$native_after->{users}->{'other@pve'}}), 1, 'native secondary deletion preserves every other account');
    my ($secondary_repeat) = http_call('POST', $secondary_path, $secondary_body, $csrf, $cookie);
    is($secondary_repeat->code, 401, 'repeated native secondary removal is rejected without another write');
    is(scalar(split(/\n/, read_bytes("$public/native-tfa-writes"))), 1, 'secondary removal commits exactly one native fixture write');
    my ($u2f_secondary) = http_call('POST', $secondary_path, {id => 'own-u2f-key', password => 'fixture-password'}, $csrf, $cookie);
    is($u2f_secondary->code, 200, 'the same protected bridge supports owned legacy U2F entries');
    my $remaining_native = $json->decode(read_bytes("$public/native-tfa.json"))->{users}->{'alice@pve'};
    is_deeply([sort(map { $_->{type} } @$remaining_native)], ['recovery', 'totp'], 'native TOTP and recovery factors remain unchanged');
    my $native_retained_bytes = read_bytes("$public/native-tfa.json");
    my $user_retained_bytes = read_bytes($userfile);
    my $last_factor_user = PVE::AccessControl::parse_user_config($userfile, $user_retained_bytes);
    $last_factor_user->{users}->{'alice@pve'}->{keys} = 'x';
    write_bytes($userfile, PVE::AccessControl::write_user_config($userfile, $last_factor_user), 0644);
    my $last_factor_state = $json->decode($native_retained_bytes);
    $last_factor_state->{users}->{'alice@pve'} = [{id => 'only-native-key', type => 'webauthn'}];
    write_bytes("$public/native-tfa.json", $json->encode($last_factor_state), 0644);
    my ($last_secondary) = http_call('POST', $secondary_path, {id => 'only-native-key', password => 'fixture-password'}, $csrf, $cookie);
    is($last_secondary->code, 200, 'last native second factor removal completes the actual native cleanup branch');
    my $last_factor_cleaned = PVE::AccessControl::parse_user_config($userfile, read_bytes($userfile));
    ok(!defined($last_factor_cleaned->{users}->{'alice@pve'}->{keys}), 'native user.cfg TFA marker is cleared in the isolated native writer');
    write_bytes($userfile, $user_retained_bytes, 0644);
    write_bytes("$public/native-tfa.json", $native_retained_bytes, 0644);
    for my $path ('/nodes/localhost/status', '/access/users', '/cluster/resources', '/../api2/json/nodes/localhost/status') {
        my ($response) = http_call('GET', $path, undef, undef, $cookie);
        is($response->code, 403, 'fixture refuses every unrelated native privileged route');
    }
    my ($missing_marker) = http_call('POST', '/sll-passkeys/login-begin', {});
    is($missing_marker->code, 401, 'anonymous begin requires non-simple header');
    my ($bad_method) = http_call('GET', '/sll-passkeys/login-begin');
    is($bad_method->code, 401, 'wrong method retains native authentication');
    my ($api_token) = http_call('GET', '/sll-passkeys/status', undef, undef, undef, {Authorization => 'PVEAPIToken=alice@pve!test=never-real'});
    is($api_token->code, 401, 'API tokens denied by public hook');
    my ($list_missing_csrf) = http_call('POST', '/sll-passkeys/register-begin', {password => 'fixture-password', description => 'Device'}, undef, $cookie);
    is($list_missing_csrf->code, 401, 'real native unprivileged CSRF check protects registration');
    my ($register_response, $begin) = http_call('POST', '/sll-passkeys/register-begin', {password => 'fixture-password', description => 'Device'}, $csrf, $cookie);
    is($register_response->code, 200, 'native full cookie and fresh fixture password begin registration');
    ok($begin && $begin->{ceremony}, 'registration state returned through native JSON parser');
    my $registration = proof('register', $begin);
    my ($complete_response, $credential) = http_call('POST', '/sll-passkeys/register-finish', {ceremony => $begin->{ceremony}, response => $json->encode($registration)}, $csrf, $cookie);
    is($complete_response->code, 200, 'real ES256 WebAuthn registration verifies through production bridge');
    like($credential->{id} // '', qr/\A[0-9a-f]{64}\z/, 'metadata identifier returned');
    my $mode_native = $json->decode(read_bytes("$public/native-tfa.json"));
    push @{$mode_native->{users}->{'alice@pve'}}, {id => 'mode-native-key', type => 'webauthn', enable => JSON::PP::false},
        {id => 'mode-second-key', type => 'u2f', enable => JSON::PP::false};
    write_bytes("$public/native-tfa.json", $json->encode($mode_native), 0644);
    my ($mode_response, $mode) = http_call('GET', '/sll-passkeys/mode', undef, undef, $cookie);
    is($mode_response->code, 200, 'native HTTP reads only the current account passkey role');
    ok($mode->{mode} eq 'alternative' && $mode->{can_change} && $mode->{primary_ready} && $mode->{primary_key_count} == 1,
        'authoritative alternative mode reports a genuinely enrolled current-generation primary credential');
    my ($anonymous_mode) = http_call('GET', '/sll-passkeys/mode');
    is($anonymous_mode->code, 401, 'per-user mode metadata remains protected');
    my $mode_body = {mode => 'two_factor', key_id => 'mode-native-key', expected_revision => $mode->{revision}, password => 'fixture-password'};
    my ($mode_csrf) = http_call('POST', '/sll-passkeys/mode', $mode_body, undef, $cookie);
    is($mode_csrf->code, 401, 'native CSRF guards role changes carrying a body-only password');
    my ($mode_other) = http_call('POST', '/sll-passkeys/mode', {%$mode_body, userid => 'other@pve'}, $csrf, $cookie);
    is($mode_other->code, 400, 'role mutation never accepts a different account');
    my ($mode_stale) = http_call('POST', '/sll-passkeys/mode', {%$mode_body, expected_revision => '0' x 64}, $csrf, $cookie);
    is($mode_stale->code, 409, 'actual native HTTP rejects a stale per-user role revision');
    my ($mode_wrong_password) = http_call('POST', '/sll-passkeys/mode', {%$mode_body, password => 'wrong-password'}, $csrf, $cookie);
    is($mode_wrong_password->code, 401, 'native role mutation requires a fresh current password');
    my ($mode_foreign_key) = http_call('POST', '/sll-passkeys/mode', {%$mode_body, key_id => 'other-native-key'}, $csrf, $cookie);
    is($mode_foreign_key->code, 400, 'a mode change cannot activate another user security key');
    my ($two_factor_response, $two_factor) = http_call('POST', '/sll-passkeys/mode', $mode_body, $csrf, $cookie);
    is($two_factor_response->code, 200, 'native HTTP commits the selected owned second-factor flag');
    ok($two_factor->{mode} eq 'two_factor' && $two_factor->{enabled_native_key_count} == 1 && !$two_factor->{primary_ready},
        'second-factor mode is persisted and disables primary eligibility while retaining primary records');
    my (undef, $blocked_primary_begin) = http_call('POST', '/sll-passkeys/login-begin', {}, 'SLL-Passkey-Login');
    my $blocked_primary_assertion = proof('assert', $blocked_primary_begin);
    my ($blocked_primary, $blocked_primary_result) = http_call('POST', '/sll-passkeys/login-finish',
        {ceremony => $blocked_primary_begin->{ceremony}, response => $json->encode($blocked_primary_assertion)}, $blocked_primary_begin->{nonce});
    is($blocked_primary->code, 401, 'a real valid ES256 primary assertion cannot bypass the second-factor role');
    ok(!$blocked_primary_result || (!$blocked_primary_result->{ticket} && !$blocked_primary_result->{cap}), 'blocked role never issues native ticket or capabilities');
    my ($native_password_response, $native_password_partial) = http_call('POST', '/access/ticket', {username => 'alice@pve', password => 'fixture-password'});
    is($native_password_response->code, 200, 'native password route remains usable in the second-factor role');
    ok($native_password_partial->{NeedTFA} && !$native_password_partial->{cap}, 'password route still requires its native second-factor continuation');
    my ($native_key_finish, $native_key_session) = http_call('POST', '/access/ticket', {username => 'alice@pve',
        password => 'webauthn:fixture-native-proof', 'tfa-challenge' => $native_password_partial->{ticket}});
    is($native_key_finish->code, 200, 'native second-factor protocol completes only through its existing continuation endpoint');
    ok($native_key_session->{cap}, 'native password plus second-factor continuation alone grants the session');
    my $several_native = $json->decode(read_bytes("$public/native-tfa.json"));
    $_->{enable} = JSON::PP::true for grep { $_->{id} eq 'mode-second-key' } @{$several_native->{users}->{'alice@pve'}};
    write_bytes("$public/native-tfa.json", $json->encode($several_native), 0644);
    my (undef, $several_mode) = http_call('GET', '/sll-passkeys/mode', undef, undef, $cookie);
    my $native_writes_before_alt = scalar(split(/\n/, read_bytes("$public/native-tfa-writes")));
    my ($alternative_response, $alternative) = http_call('POST', '/sll-passkeys/mode',
        {mode => 'alternative', expected_revision => $several_mode->{revision}, password => 'fixture-password'}, $csrf, $cookie);
    is($alternative_response->code, 200, 'native HTTP restores alternative mode with an atomic multi-key update');
    ok($alternative->{mode} eq 'alternative' && !$alternative->{enabled_native_key_count} && $alternative->{primary_ready},
        'all native passkey factors are disabled and actual primary eligibility returns');
    is(scalar(split(/\n/, read_bytes("$public/native-tfa-writes"))) - $native_writes_before_alt, 1,
        'multi-key alternative transition performs exactly one native CFS write');
    ok($alternative->{other_factors_enabled} && $alternative->{native_key_count} == 2, 'native credentials and separate TOTP/recovery factors are retained');
    is(scalar(@{$json->decode(read_bytes("$public/native-tfa.json"))->{users}->{'other@pve'}}), 1, 'native role transition preserves other users');
    write_bytes("$public/realm-tfa-required", 'managed', 0644);
    my (undef, $managed_mode) = http_call('GET', '/sll-passkeys/mode', undef, undef, $cookie);
    ok(!$managed_mode->{can_change} && $managed_mode->{reason}, 'mandatory realm MFA makes the role control unavailable');
    my ($managed_mode_change) = http_call('POST', '/sll-passkeys/mode', {mode => 'two_factor', key_id => 'mode-native-key',
        expected_revision => $managed_mode->{revision}, password => 'fixture-password'}, $csrf, $cookie);
    is($managed_mode_change->code, 400, 'native role endpoint cannot override realm-managed factor policy');
    unlink("$public/realm-tfa-required") or die $!;
    my ($login_begin_response, $login_begin) = http_call('POST', '/sll-passkeys/login-begin', {}, 'SLL-Passkey-Login');
    is($login_begin_response->code, 200, 'public discoverable login begin forwarded');
    ok(!exists($login_begin->{publicKey}->{allowCredentials}), 'discoverable request contains no account credential list');
    my $assertion = proof('assert', $login_begin);
    my ($login_response, $login) = http_call('POST', '/sll-passkeys/login-finish', {ceremony => $login_begin->{ceremony}, response => $json->encode($assertion)}, $login_begin->{nonce});
    is($login_response->code, 200, 'actual native proxy preserves nonce header for real assertion verification');
    is($login->{username}, 'alice@pve', 'verified credential maps to fictional native account');
    ok($login->{ticket} && $login->{CSRFPreventionToken} && $login->{cap}, 'normal native ticket CSRF and capabilities returned');
    my ($authenticated_response, $credentials) = http_call('GET', '/sll-passkeys/credentials', undef, undef, $login->{ticket});
    is($authenticated_response->code, 200, 'issued memory-key native ticket authenticates through native gate');
    is(scalar(@{$credentials->{credentials}}), 1, 'only own primary credential metadata listed');
    my ($replay) = http_call('POST', '/sll-passkeys/login-finish', {ceremony => $login_begin->{ceremony}, response => $json->encode($assertion)}, $login_begin->{nonce});
    is($replay->code, 401, 'native HTTP replay is denied after one-time consumption');
    my (undef, $wrong_nonce_begin) = http_call('POST', '/sll-passkeys/login-begin', {}, 'SLL-Passkey-Login');
    my $wrong_nonce_assertion = proof('assert', $wrong_nonce_begin);
    my ($wrong_nonce) = http_call('POST', '/sll-passkeys/login-finish', {ceremony => $wrong_nonce_begin->{ceremony}, response => $json->encode($wrong_nonce_assertion)}, 'x' x 43);
    is($wrong_nonce->code, 401, 'wrong browser nonce fails through native forwarding');
    for my $case (['missing UV', {uv => JSON::PP::false}], ['wrong origin', {origin => 'https://unrelated.example'}], ['invalid signature', {}]) {
        my ($label, $parameters) = @$case;
        my (undef, $negative_begin) = http_call('POST', '/sll-passkeys/login-begin', {}, 'SLL-Passkey-Login');
        my $negative_assertion = proof('assert', $negative_begin, $parameters);
        if ($label eq 'invalid signature') {
            my $signature = $negative_assertion->{response}->{signature};
            substr($signature, 0, 1) = substr($signature, 0, 1) eq 'A' ? 'B' : 'A';
            $negative_assertion->{response}->{signature} = $signature;
        }
        my ($negative_response, $negative_data) = http_call('POST', '/sll-passkeys/login-finish',
            {ceremony => $negative_begin->{ceremony}, response => $json->encode($negative_assertion)}, $negative_begin->{nonce});
        is($negative_response->code, 401, "real native HTTP rejects $label cryptographic proof");
        ok(!$negative_data || !$negative_data->{ticket}, 'failed proof never returns a native ticket');
    }
    write_bytes("$public/mfa-required", 'required', 0644);
    my (undef, $mfa_begin) = http_call('POST', '/sll-passkeys/login-begin', {}, 'SLL-Passkey-Login');
    my $mfa_assertion = proof('assert', $mfa_begin);
    my ($mfa_response, $mfa) = http_call('POST', '/sll-passkeys/login-finish', {ceremony => $mfa_begin->{ceremony}, response => $json->encode($mfa_assertion)}, $mfa_begin->{nonce});
    is($mfa_response->code, 200, 'existing native MFA policy produces partial success');
    ok($mfa->{NeedTFA} && !$mfa->{cap}, 'partial response has no full capabilities');
    my ($half_use) = http_call('GET', '/sll-passkeys/credentials', undef, undef, $mfa->{ticket});
    is($half_use->code, 401, 'partial native ticket cannot call authenticated credential endpoints');
    my ($half_secondary) = http_call('POST', '/sll-passkeys/remove-second-factor', {id => 'totp-key', password => 'fixture-password'}, $csrf, $mfa->{ticket});
    is($half_secondary->code, 401, 'native MFA half-ticket cannot remove second factors through the bridge');
    my ($finish_mfa_response, $full_after_mfa) = http_call('POST', '/access/ticket', {username => 'alice@pve', password => 'totp:fixture-code', 'tfa-challenge' => $mfa->{ticket}});
    is($finish_mfa_response->code, 200, 'existing native ticket endpoint completes its own MFA continuation');
    ok($full_after_mfa->{cap} && $full_after_mfa->{ticket} !~ /!tfa!/, 'native continuation alone returns full session');
    for my $case (['disabled', ':0:0:'], ['expired', ':1:1:']) {
        my ($label, $replacement) = @$case;
        my $denied_line = $userline; $denied_line =~ s/:1:0:/$replacement/;
        write_bytes($userfile, $denied_line, 0644);
        my (undef, $denied_begin) = http_call('POST', '/sll-passkeys/login-begin', {}, 'SLL-Passkey-Login');
        my $denied_assertion = proof('assert', $denied_begin);
        my ($denied_response) = http_call('POST', '/sll-passkeys/login-finish',
            {ceremony => $denied_begin->{ceremony}, response => $json->encode($denied_assertion)}, $denied_begin->{nonce});
        is($denied_response->code, 401, "native $label account denied after a valid real assertion");
        write_bytes($userfile, $userline, 0644);
    }
    write_bytes("$public/password-record", '$6$replacement$' . ('B' x 86), 0644);
    my (undef, $reset_begin) = http_call('POST', '/sll-passkeys/login-begin', {}, 'SLL-Passkey-Login');
    my $reset_assertion = proof('assert', $reset_begin);
    my ($reset_denied) = http_call('POST', '/sll-passkeys/login-finish', {ceremony => $reset_begin->{ceremony}, response => $json->encode($reset_assertion)}, $reset_begin->{nonce});
    is($reset_denied->code, 401, 'native password reset invalidates an old primary passkey');
    my ($reset_list_response, $reset_list) = http_call('GET', '/sll-passkeys/credentials', undef, undef, $login->{ticket});
    is($reset_list_response->code, 200, 'current generation can request own metadata after password reset');
    is_deeply($reset_list->{credentials}, [], 'previous generation metadata is hidden after password reset');
    my ($reset_delete) = http_call('DELETE', '/sll-passkeys/credentials/' . $credential->{id}, undef, $login->{CSRFPreventionToken}, $login->{ticket});
    cmp_ok($reset_delete->code, '>=', 400, 'current generation cannot revoke a previous-generation credential by remembered ID');
    write_bytes($userfile, '', 0644);
    my (undef, $deleted_user_begin) = http_call('POST', '/sll-passkeys/login-begin', {}, 'SLL-Passkey-Login');
    my $deleted_user_assertion = proof('assert', $deleted_user_begin);
    my ($deleted_user_denied) = http_call('POST', '/sll-passkeys/login-finish', {ceremony => $deleted_user_begin->{ceremony}, response => $json->encode($deleted_user_assertion)}, $deleted_user_begin->{nonce});
    is($deleted_user_denied->code, 401, 'deleted native account cannot use an existing primary passkey');
    write_bytes($userfile, $userline, 0644);
    my (undef, $recreated_begin) = http_call('POST', '/sll-passkeys/login-begin', {}, 'SLL-Passkey-Login');
    my $recreated_assertion = proof('assert', $recreated_begin);
    my ($recreated_denied) = http_call('POST', '/sll-passkeys/login-finish', {ceremony => $recreated_begin->{ceremony}, response => $json->encode($recreated_assertion)}, $recreated_begin->{nonce});
    is($recreated_denied->code, 401, 'same username recreated with a new password record rejects old primary passkeys');
    my ($recreated_list_response, $recreated_list) = http_call('GET', '/sll-passkeys/credentials', undef, undef, $login->{ticket});
    is($recreated_list_response->code, 200, 'recreated native identity can request own credential metadata');
    is_deeply($recreated_list->{credentials}, [], 'recreated username cannot view previous account key names or timestamps');
    write_bytes("$public/password-record", '$6$fixture$' . ('A' x 86), 0644);
    my ($remove_response) = http_call('DELETE', '/sll-passkeys/credentials/' . $credential->{id}, undef, $login->{CSRFPreventionToken}, $login->{ticket});
    is($remove_response->code, 200, 'native full session and CSRF revoke own primary credential');
    my (undef, $deleted_begin) = http_call('POST', '/sll-passkeys/login-begin', {}, 'SLL-Passkey-Login');
    my $deleted_assertion = proof('assert', $deleted_begin);
    my ($deleted) = http_call('POST', '/sll-passkeys/login-finish', {ceremony => $deleted_begin->{ceremony}, response => $json->encode($deleted_assertion)}, $deleted_begin->{nonce});
    is($deleted->code, 401, 'revoked credential no longer logs in');
    1;
};
my $error = $@;
close($driver_in) if $driver_in; close($driver_out) if $driver_out;
if ($driver_pid) { kill('TERM', $driver_pid); waitpid($driver_pid, 0); }
kill('TERM', @children) if @children;
waitpid($_, 0) for @children;
if (!$ok) {
    diag($error);
    for my $name (qw(root edge)) { my $path = "$public/$name-errors.log"; diag(read_bytes($path)) if -f $path; }
    fail('native HTTP fixture completed');
}
done_testing();
