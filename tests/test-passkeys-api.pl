#!/usr/bin/perl
# Isolated Perl bridge, authorization, native-ticket-policy and auth-hook tests.
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Basename qw(dirname);
use JSON::PP;
use Scalar::Util qw(tainted);
use IO::Select;
use IO::Handle;
use POSIX qw(_exit);
our (%METHODS, @COMMANDS, @PASSWORD_CHECKS, @TICKETS, @MFA_CALLS, @AUDIT, @AUTH_CALLS);
our @SECONDARY_DELETES;
our $NATIVE_ENTRIES = {'alice@pve' => [{id => 'owned-native-key', type => 'webauthn', enable => JSON::PP::false}, {id => 'totp-key', type => 'totp'}, {id => 'recovery-key', type => 'recovery'}],
    'root@pam' => [{id => 'root-native-key', type => 'u2f', enable => JSON::PP::false}], 'other@pve' => [{id => 'other-native-key', type => 'webauthn'}]};
our $USER_CONFIG = {users => {'alice@pve' => {enable => 1, expire => 0, keys => 'x'}, 'root@pam' => {enable => 1, expire => 0, keys => 'x'}}};
our ($NATIVE_WRITES, $NATIVE_UPDATES, $NATIVE_UPDATE_FAIL, $NATIVE_SERIALIZE_FAIL, $NATIVE_WRITE_FAIL, $NATIVE_WRITE_FAIL_AFTER) = (0) x 6;
our ($MODE_LOCK_HOOK, $MFA_HOOK);
our $CORE_KEY_COUNT = 0;
our $USER = 'alice@pve';
our $CREDENTIALS = {ticket => 'full:alice@pve', token => 'csrf:alice@pve'};
our $DC = {webauthn => {id => 'pve.example.test', origin => 'https://pve.example.test', rp => 'Fixture PVE'}};
our $DOMAINS = {ids => {pve => {type => 'pve'}, pam => {type => 'pam'}, ldap => {type => 'ldap'}}};
our ($DISABLED, $EXPIRED, $MFA_FAIL, $CORE_FAIL, $MALFORMED, $OVERSIZED, $PAM_BAD) = (0) x 7;
our $CORE_USER = 'alice@pve';
our $CORE_BINDING;
our $PASSWORD_HASH = '$6$fixture$' . ('A' x 86);
our $PASSWORD_VALUE = 'fixture-password';
our $PASSWORD_ACTION = '';
our $PASSWORD_STEP = 0;
our $MFA;
our $PAM_STATUS = 'P';
our $CLIENT = '127.0.0.1';
BEGIN {
    package Authen::PAM;
    use base 'Exporter';
    our @EXPORT_OK = qw(PAM_CONV_ERR PAM_RHOST PAM_SUCCESS);
    our %EXPORT_TAGS = (constants => \@EXPORT_OK);
    sub PAM_CONV_ERR () { 19 }
    sub PAM_RHOST () { 4 }
    sub PAM_SUCCESS () { 0 }
    sub new { bless {}, __PACKAGE__ }
    sub pam_set_item { return 0 }
    sub pam_acct_mgmt { $main::PAM_BAD ? 13 : 0 }
    $INC{'Authen/PAM.pm'} = 1;
    package PVE::RESTHandler;
    sub register_method { $main::METHODS{$_[1]->{name}} = $_[1]; }
    $INC{'PVE/RESTHandler.pm'} = 1;
    package PVE::Exception;
    use base 'Exporter';
    our @EXPORT_OK = qw(raise);
    sub raise { my ($message, %opt) = @_; die "$opt{code} $message\n"; }
    $INC{'PVE/Exception.pm'} = 1;
    package PVE::Cluster;
    sub cfs_read_file { $_[0] eq 'datacenter.cfg' ? $main::DC : $_[0] eq 'user.cfg' ? $main::USER_CONFIG : $_[0] eq 'priv/tfa.cfg' ? bless({entries => $main::NATIVE_ENTRIES}, 'FixtureNativeConfig') : $_[0] eq 'priv/shadow.cfg' ? {users => {alice => {shadow => $main::PASSWORD_HASH}}} : $main::DOMAINS }
    sub cfs_write_file {
        die 'unexpected native write' if $_[0] ne 'priv/tfa.cfg';
        die 'native write failure' if $main::NATIVE_WRITE_FAIL;
        $main::NATIVE_ENTRIES = JSON::PP->new->decode(JSON::PP->new->encode($_[1]->{entries}));
        $main::NATIVE_WRITES++;
        die 'ambiguous committed native write' if $main::NATIVE_WRITE_FAIL_AFTER;
    }
    sub cfs_update { return 1; }
    sub log_msg { push @main::AUDIT, join(' ', @_); }
    $INC{'PVE/Cluster.pm'} = 1;
    package FixtureNativeConfig;
    sub api_list_user_tfa { $_[0]->{entries}->{$_[1]} // [] }
    sub write { die 'native serializer failure' if $main::NATIVE_SERIALIZE_FAIL; JSON::PP->new->encode({entries => $_[0]->{entries}}) }
    sub api_update_tfa_entry {
        my ($self, $user, $id, $description, $enable) = @_;
        $main::NATIVE_UPDATES++;
        die 'native update failure' if $main::NATIVE_UPDATE_FAIL && $main::NATIVE_UPDATES == $main::NATIVE_UPDATE_FAIL;
        my @entry = grep { $_->{id} eq $id } @{$self->{entries}->{$user} // []};
        die 'native key missing' if @entry != 1;
        $entry[0]->{enable} = $enable ? JSON::PP::true : JSON::PP::false;
    }
    package PVE::SafeSyslog;
    sub syslog { my ($level, $format, @values) = @_; push @main::AUDIT, $level . ' ' . sprintf($format, @values); }
    $INC{'PVE/SafeSyslog.pm'} = 1;
    package PVE::Auth::Plugin;
    sub verify_username { $_[0] =~ /\A(([^\s:\/@]+)\@([A-Za-z][A-Za-z0-9_-]*))\z/ or die 'bad user'; return wantarray ? ($1, $2, $3) : $1; }
    sub lookup { 'FixturePasswordPlugin' }
    $INC{'PVE/Auth/Plugin.pm'} = 1;
    package FixturePasswordPlugin;
    sub authenticate_user {
        my ($class, $config, $realm, $ruid, $password) = @_;
        push @main::PASSWORD_CHECKS, [$realm, $ruid];
        die 'private PAM diagnostic' if $password ne $main::PASSWORD_VALUE;
        $main::PASSWORD_STEP++;
        if ($main::PASSWORD_ACTION && $main::PASSWORD_STEP == 1) {
            $main::PASSWORD_HASH = '$6$rotated$' . ('C' x 86);
            $main::PASSWORD_VALUE = 'different-reset-password' if $main::PASSWORD_ACTION eq 'reset';
        } elsif ($main::PASSWORD_ACTION eq 'twice' && $main::PASSWORD_STEP == 2) {
            $main::PASSWORD_HASH = '$6$second$' . ('D' x 86);
        }
        return 1;
    }
    package PVE::AccessControl;
    sub verify_ticket {
        my ($ticket) = @_;
        return ({type => 'new'}) if $ticket eq 'half-new';
        return ('alice@pve', 0, {type => 'tfa'}) if $ticket eq 'half-old';
        return $ticket =~ /\Afull:(.+)\z/ ? ($1, 0, undef) : ();
    }
    sub lookup_username { $_[0] }
    sub check_user_enabled { die 'disabled user' if $main::DISABLED; die 'expired user' if $main::EXPIRED; return 1; }
    sub parse_priv_tfa_config { bless JSON::PP->new->decode($_[1]), 'FixtureNativeConfig' }
    sub lock_tfa_config { if ($main::MODE_LOCK_HOOK) { my $hook = $main::MODE_LOCK_HOOK; local $main::MODE_LOCK_HOOK; $hook->(); } return $_[0]->(); }
    sub verify_csrf_prevention_token { die 'invalid CSRF' if $_[1] ne 'csrf:' . $_[0]; return 1; }
    sub assemble_ticket { push @main::TICKETS, [@_]; return 'NATIVE:' . $_[0]; }
    sub assemble_csrf_prevention_token { 'csrf:' . $_[0] }
    sub authenticate_2nd_new { push @main::MFA_CALLS, [@_]; die 'private MFA diagnostic' if $main::MFA_FAIL; $main::MFA_HOOK->() if $main::MFA_HOOK; return $main::MFA; }
    $INC{'PVE/AccessControl.pm'} = 1;
    package PVE::API2::TFA;
    our $OPTIONAL_PASSWORD_SCHEMA = {type => 'string', optional => 1, minLength => 5, maxLength => 64};
    sub list_user_tfa { return $main::NATIVE_ENTRIES->{$_[1]->{userid}} // []; }
    sub delete_tfa {
        my ($class, $param) = @_;
        die 'wrong native account' if $param->{userid} ne $main::USER;
        die 'private native password diagnostic' if $main::USER ne 'root@pam' && ($param->{password} // '') ne 'fixture-password';
        push @main::SECONDARY_DELETES, {user => $param->{userid}, id => $param->{id}, has_password => exists($param->{password}) ? 1 : 0};
        $main::NATIVE_ENTRIES->{$param->{userid}} = [grep { $_->{id} ne $param->{id} } @{$main::NATIVE_ENTRIES->{$param->{userid}}}];
        return undef;
    }
    $INC{'PVE/API2/TFA.pm'} = 1;
    package PVE::RPCEnvironment;
    sub get { bless {}, __PACKAGE__ }
    sub get_user { $main::USER }
    sub get_credentials { $main::CREDENTIALS }
    sub get_client_ip { $main::CLIENT }
    sub check_user_enabled { die 'disabled user' if $main::DISABLED; die 'expired user' if $main::EXPIRED; die 'no such user' if $_[1] !~ /\A(?:alice|root)\@(?:pam|pve|ldap)\z/; return 1; }
    sub compute_api_permission { return {dc => {'Sys.Audit' => 1}}; }
    $INC{'PVE/RPCEnvironment.pm'} = 1;
    package PVE::Tools;
    sub run_fork { $_[0]->() }
    sub run_command {
        my ($argv, %opts) = @_;
        die 'tainted command argument' if grep { Scalar::Util::tainted($_) } @$argv;
        if ($argv->[0] eq '/usr/bin/getent') {
            die 'invalid account-state command' if @$argv != 6 || $argv->[1] ne '-s' || $argv->[2] ne 'files' || $argv->[3] ne 'shadow' || $argv->[4] ne '--';
            $opts{outfunc}->($argv->[5] . ':' . $main::PASSWORD_HASH . ':20000:0:99999:7:::'); return;
        }
        if ($argv->[0] eq '/usr/bin/passwd') {
            die 'invalid passwd command' if @$argv != 4 || $argv->[1] ne '-S' || $argv->[2] ne '--';
            $opts{outfunc}->("$argv->[3] $main::PAM_STATUS 2026-01-01 0 99999 7 -1"); return;
        }
        die 'invalid Python command' if @$argv != 3 || $argv->[0] ne '/usr/bin/python3' || $argv->[1] ne '-I';
        my $request = JSON::PP->new->utf8->decode($opts{input});
        die 'password crossed crypto boundary' if exists($request->{password}) || $opts{input} =~ /fixture-password/;
        push @main::COMMANDS, $request;
        die 'private crypto diagnostic' if $main::CORE_FAIL;
        return $opts{outfunc}->('not JSON') if $main::MALFORMED;
        return $opts{outfunc}->('x' x 131073) if $main::OVERSIZED;
        my $op = $request->{op};
        my $result = $op eq 'status' ? {supported => 1} : $op eq 'list' ? {credentials => [map { {id => 'e' x 64} } 1 .. $main::CORE_KEY_COUNT]} :
            $op eq 'register_begin' ? {ceremony => 'a' x 32, publicKey => {challenge => 'fixture'}} :
            $op eq 'register_finish' ? {id => 'b' x 64, description => 'Device'} :
            $op eq 'login_begin' ? {ceremony => 'c' x 32, nonce => 'n' x 43, publicKey => {challenge => 'fixture'}} :
            $op eq 'login_finish' ? {user => $main::CORE_USER, binding => $main::CORE_BINDING // PVE::API2::SLLPasskeys::account_binding($main::CORE_USER)} : {removed => JSON::PP::true};
        $opts{outfunc}->(JSON::PP->new->utf8->encode($result));
    }
    $INC{'PVE/Tools.pm'} = 1;
    package PVE::HTTPServer;
    sub auth_handler {
        push @main::AUTH_CALLS, [@_];
        die 'No ticket' if $_[2] ne '/access/ticket' && !$_[3];
        return {ticket => $_[3], token => $_[4], api_token => $_[5], userid => undef};
    }
    $INC{'PVE/HTTPServer.pm'} = 1;
}
my $root = tempdir('.sll-passkey-api-XXXXXX', DIR => '/root', CLEANUP => 1);
my $source;
{ open(my $fh, '<', dirname(__FILE__) . '/../PVE/API2/SLLPasskeys.pm') or die $!; local $/; $source = <$fh>; }
$source =~ s{\Q/var/lib/proxmox-makeover/control.lock\E}{$root/control.lock}g;
$source =~ s{\Q/var/lib/proxmox-makeover/maintenance.json\E}{$root/maintenance}g;
$source =~ s{\Q/usr/local/libexec/proxmox-makeover/passkeys.py\E}{$root/passkeys.py}g;
my ($isolated) = $source =~ /\A([\s\S]*)\z/;
my $loaded = eval $isolated; die $@ if !$loaded;
# Command execution is already stubbed above. The production ownership/path
# verifier remains tested separately by the PVE-only HTTP integration fixture.
{ no warnings qw(redefine once); *PVE::API2::SLLPasskeys::checked_core = sub { '/fixture/passkeys.py' }; *PVE::API2::SLLPasskeys::pam_identity = sub { return (10001, 10001); }; }
sub call_api { $METHODS{$_[0]}->{code}->($_[1] // {}) }
sub error_from { eval { $_[0]->(); 1 }; return "$@" }
sub logged_in {
    my ($user) = @_;
    $USER = $user; $CREDENTIALS = {ticket => 'full:' . $user, token => 'csrf:' . $user};
}
my $JSON = JSON::PP->new->canonical;
my $assertion = $JSON->encode({type => 'public-key', response => {proof => 'fixture-assertion-secret'}});
my $finish = {ceremony => 'c' x 32, response => $assertion};
sub primary_login {
    local $USER = undef;
    local $CREDENTIALS = {token => 'n' x 43};
    return call_api('login_finish', $finish);
}
for my $name (sort keys %METHODS) {
    ok($METHODS{$name}->{protected}, "$name native privileged routing");
    ok(!$METHODS{$name}->{allowtoken}, "$name rejects API-token authorization");
    is($METHODS{$name}->{parameters}->{additionalProperties}, 0, "$name rejects unknown request fields");
}
my $status = call_api('status');
is($status->{version}, '0.1-beta', 'public status version');
ok($status->{secondary_removal}, 'resident backend advertises protected secondary-removal support');
ok($status->{per_user_mode}, 'resident backend advertises actual per-user mode enforcement');
ok($status->{supported} && $status->{primary_passkeys}, 'public capability status');
ok(!exists($status->{user}) && !exists($status->{credentials}), 'public status contains no account metadata');
my $status_calls = scalar(@COMMANDS);
call_api('status'); call_api('status');
is(scalar(@COMMANDS), $status_calls, 'public status caches Python availability');
for my $bad_origin ('http://pve.example.test', 'https://pve.example.test/path', 'https://user@pve.example.test', 'https://elsewhere.test', 'https://pve.example.test:0') {
    local $DC = {webauthn => {%{$DC->{webauthn}}, origin => $bad_origin}};
    ok(!call_api('status')->{supported}, 'invalid native RP origin disables primary passkeys');
}
{
    local $DC = {webauthn => {id => 'example.test', origin => 'https://pve.example.test:8006', rp => 'Parent'}};
    is(PVE::API2::SLLPasskeys::trusted_rp()->{id}, 'example.test', 'configured parent-domain RP preserved');
}
for my $ticket ('', 'half-new', 'half-old', 'full:other@pve') {
    local $CREDENTIALS = {ticket => $ticket, token => 'csrf:alice@pve'};
    like(error_from(sub { call_api('credentials') }), qr/complete interactive/, 'management requires a matching full native ticket');
}
{
    local $USER = 'alice@pve!token'; local $CREDENTIALS = {api_token => 'fixture'};
    like(error_from(sub { call_api('credentials') }), qr/interactive/, 'token auth denied for management');
}
{
    local $CREDENTIALS = {ticket => 'full:alice@pve', token => 'invalid'};
    like(error_from(sub { call_api('register_begin', {password => 'fixture-password', description => 'Device'}) }), qr/CSRF/, 'native CSRF checked before registration');
    like(error_from(sub { call_api('delete', {id => 'b' x 64}) }), qr/CSRF/, 'native CSRF checked before deletion');
}
call_api('credentials');
is($COMMANDS[-1]->{binding}, PVE::API2::SLLPasskeys::account_binding('alice@pve'), 'credential metadata is scoped to the fresh native account generation');
my $password_checks_before = scalar(@PASSWORD_CHECKS);
my $registration = call_api('register_begin', {password => 'fixture-password', description => 'Device'});
is($registration->{ceremony}, 'a' x 32, 'authenticated registration begins');
is(scalar(@PASSWORD_CHECKS) - $password_checks_before, 1, 'stable account generation requires exactly one native password verification');
is_deeply($PASSWORD_CHECKS[-1], ['pve', 'alice'], 'fresh password checked by native realm plugin');
is($COMMANDS[-1]->{user}, 'alice@pve', 'registration bound to current authenticated user');
is($COMMANDS[-1]->{client}, '127.0.0.1', 'trusted native client address supplied to rate limiting');
ok(!exists($COMMANDS[-1]->{password}), 'password never passed to crypto bridge');
like(error_from(sub { call_api('register_begin', {password => 'wrong', description => 'Device'}) }), qr/401 authentication failure/, 'native password failure is generic');
like(error_from(sub { call_api('register_begin', {password => '', description => 'Device'}) }), qr/401 authentication failure/, 'empty password rejected');
like(error_from(sub { call_api('register_begin', {password => 'x' x 1025, description => 'Device'}) }), qr/401 authentication failure/, 'oversized password rejected');
for my $action ('reset', 'rehash', 'twice') {
    local $PASSWORD_ACTION = $action; local $PASSWORD_STEP = 0;
    local $PASSWORD_HASH = $PASSWORD_HASH; local $PASSWORD_VALUE = 'fixture-password';
    my $checks_before = scalar(@PASSWORD_CHECKS);
    if ($action eq 'rehash') {
        my $rehash_registration = call_api('register_begin', {password => 'fixture-password', description => 'Device'});
        is($rehash_registration->{ceremony}, 'a' x 32, 'transparent native PVE rehash permits enrollment after a fresh second password proof');
        is($COMMANDS[-1]->{binding}, PVE::API2::SLLPasskeys::account_binding('alice@pve'), 'rehash enrollment uses only the freshly verified generation');
    } else {
        like(error_from(sub { call_api('register_begin', {password => 'fixture-password', description => 'Device'}) }), qr/401 authentication failure/,
            $action eq 'reset' ? 'different-password reset rejects the old proof on native retry' : 'a second generation race during retry rejects enrollment');
    }
    is(scalar(@PASSWORD_CHECKS) - $checks_before, 2, 'PVE generation change is bounded to two native password verifications');
}
logged_in('alice@pam');
{
    local $PASSWORD_ACTION = 'rehash'; local $PASSWORD_STEP = 0; local $PASSWORD_HASH = $PASSWORD_HASH;
    my $checks_before = scalar(@PASSWORD_CHECKS);
    like(error_from(sub { call_api('register_begin', {password => 'fixture-password', description => 'Device'}) }), qr/401 authentication failure/, 'PAM generation changes retain the strict rejection policy');
    is(scalar(@PASSWORD_CHECKS) - $checks_before, 1, 'PAM never retries native password verification');
}
logged_in('root@pam');
call_api('register_begin', {password => 'fixture-password', description => 'Root device'});
is_deeply($PASSWORD_CHECKS[-1], ['pam', 'root'], 'root enrollment also requires fresh native primary password');
logged_in('alice@pve');
call_api('register_finish', {ceremony => 'a' x 32, response => $assertion});
call_api('delete', {id => 'b' x 64});
is($COMMANDS[-1]->{user}, 'alice@pve', 'deletion bound to current authenticated user');
is($COMMANDS[-1]->{binding}, PVE::API2::SLLPasskeys::account_binding('alice@pve'), 'credential deletion is scoped to the fresh native account generation');
like(error_from(sub { call_api('delete', {id => '../../etc/pve'}) }), qr/invalid passkey id/, 'credential path traversal rejected');
{
    local $NATIVE_ENTRIES = JSON::PP->new->decode(JSON::PP->new->encode($NATIVE_ENTRIES));
    local $CORE_KEY_COUNT = 0;
    $NATIVE_ENTRIES->{'alice@pve'} = [];
    my $empty = JSON::PP->new->canonical->encode(call_api('get_mode'));
    like($empty, qr/"enabled_native_key_count":0(?:,|\})/, 'empty native count is a JSON number rather than a string');
    like($empty, qr/"primary_key_count":0(?:,|\})/, 'empty primary count is a JSON number rather than a string');
}
{
    local $NATIVE_ENTRIES = JSON::PP->new->decode(JSON::PP->new->encode($NATIVE_ENTRIES));
    local $PASSWORD_HASH = $PASSWORD_HASH;
    local $CORE_KEY_COUNT = 1;
    local $NATIVE_WRITES = 0;
    push @{$NATIVE_ENTRIES->{'alice@pve'}}, {id => 'second-native-key', type => 'u2f', enable => JSON::PP::false};
    my $state = call_api('get_mode');
    is($state->{mode}, 'alternative', 'no enabled native passkey factor means the persisted default alternative role');
    ok($state->{can_change} && $state->{primary_ready} && $state->{primary_key_count} == 1, 'role status reports current-node primary readiness and own permission');
    ok($state->{other_factors_enabled}, 'role status discloses separate native factors');
    unlike(JSON::PP->new->encode($state), qr/other-native-key|other\@pve|A{86}/, 'role response exposes no other user or account-generation material');
    { local $CREDENTIALS = {ticket => 'full:alice@pve', token => 'invalid'};
      like(error_from(sub { call_api('set_mode', {mode => 'two_factor', key_id => 'owned-native-key', expected_revision => $state->{revision}, password => 'fixture-password'}) }), qr/CSRF/, 'mode mutation requires native CSRF'); }
    for my $password ('wrong-password', '') {
        like(error_from(sub { call_api('set_mode', {mode => 'two_factor', key_id => 'owned-native-key', expected_revision => $state->{revision}, password => $password}) }), qr/401/, 'mode changes require a fresh current password');
    }
    for my $id (undef, 'other-native-key', 'totp-key', 'recovery-key') {
        like(error_from(sub { call_api('set_mode', {mode => 'two_factor', defined($id) ? (key_id => $id) : (), expected_revision => $state->{revision}, password => 'fixture-password'}) }), qr/400/, 'two-factor role requires an explicitly selected owned WebAuthn or U2F key');
    }
    like(error_from(sub { call_api('set_mode', {mode => 'two_factor', key_id => 'owned-native-key', expected_revision => '0' x 64, password => 'fixture-password'}) }), qr/409/, 'stale role revision is rejected before a native write');
    is($NATIVE_WRITES, 0, 'all precondition failures leave native factor flags unchanged');
    my $other_before = JSON::PP->new->canonical->encode($NATIVE_ENTRIES->{'other@pve'});
    $state = call_api('set_mode', {mode => 'two_factor', key_id => 'owned-native-key', expected_revision => $state->{revision}, password => 'fixture-password'});
    is($state->{mode}, 'two_factor', 'enabling the selected native key commits the actual second-factor role');
    is($state->{enabled_native_key_count}, 1, 'only the explicitly selected native key is enabled');
    ok(!$state->{primary_ready} && $state->{primary_key_count} == 1, 'registered primary records are retained but ineligible in second-factor mode');
    is($NATIVE_WRITES, 1, 'a role transition uses exactly one native factor write');
    is(JSON::PP->new->canonical->encode($NATIVE_ENTRIES->{'other@pve'}), $other_before, 'role change preserves other accounts');
    my $tickets_before = scalar(@TICKETS);
    like(error_from(sub { primary_login() }), qr/401/, 'second-factor role blocks a valid primary proof from issuing any native ticket');
    is(scalar(@TICKETS), $tickets_before, 'blocked primary proof never issues a full or partial ticket');
    {
        local $DOMAINS = JSON::PP->new->decode(JSON::PP->new->encode($DOMAINS));
        $DOMAINS->{ids}->{pve}->{tfa} = 'type=oath';
        my $managed = call_api('get_mode');
        ok(!$managed->{can_change} && $managed->{reason}, 'mandatory realm MFA locks passkey role changes');
        $DOMAINS->{ids}->{pve}->{tfa} = 'type=yubico,key=fictional-private-realm-key';
        $DOMAINS->{ids}->{pve}->{irrelevant_secret} = 'fictional-private-field';
        is(call_api('get_mode')->{revision}, $managed->{revision}, 'locked realm revision never fingerprints private or irrelevant realm material');
        like(error_from(sub { call_api('set_mode', {mode => 'alternative', expected_revision => $managed->{revision}, password => 'fixture-password'}) }), qr/400/, 'mandatory realm policy cannot be disabled by a role transition');
    }
    {
        local $USER_CONFIG = JSON::PP->new->decode(JSON::PP->new->encode($USER_CONFIG));
        $USER_CONFIG->{users}->{'alice@pve'}->{keys} = 'fixture-legacy-factor';
        my $legacy = call_api('get_mode');
        ok(!$legacy->{can_change}, 'legacy native factor configuration cannot be silently migrated');
        $USER_CONFIG->{users}->{'alice@pve'}->{keys} = 'different-fictional-legacy-factor';
        is(call_api('get_mode')->{revision}, $legacy->{revision}, 'unsupported legacy secrets never become a revision fingerprint oracle');
        like(error_from(sub { call_api('set_mode', {mode => 'alternative', expected_revision => $legacy->{revision}, password => 'fixture-password'}) }), qr/400/, 'legacy factor mode mutation is rejected without a native write');
    }
    {
        local $PASSWORD_HASH = $PASSWORD_HASH;
        local $MODE_LOCK_HOOK = sub { $PASSWORD_HASH = '$6$newgeneration$' . ('F' x 86); };
        like(error_from(sub { call_api('set_mode', {mode => 'alternative', expected_revision => $state->{revision}, password => 'fixture-password'}) }), qr/401/, 'password-generation change between proof and native lock is denied');
    }
    {
        local $MODE_LOCK_HOOK = sub { $NATIVE_ENTRIES->{'alice@pve'}->[1]->{description} = 'concurrent native edit'; };
        like(error_from(sub { call_api('set_mode', {mode => 'alternative', expected_revision => $state->{revision}, password => 'fixture-password'}) }), qr/409/, 'concurrent native metadata edit is preserved by revision checking');
    }
    $state = call_api('get_mode');
    {
        local $PASSWORD_ACTION = 'rehash'; local $PASSWORD_STEP = 0; local $PASSWORD_HASH = $PASSWORD_HASH;
        my $checks_before = scalar(@PASSWORD_CHECKS);
        $state = call_api('set_mode', {mode => 'alternative', expected_revision => $state->{revision}, password => 'fixture-password'});
        is($state->{mode}, 'alternative', 'transparent native password rehash does not spuriously invalidate the public role revision');
        is(scalar(@PASSWORD_CHECKS) - $checks_before, 2, 'rehash transition still requires the fresh stable second password proof');
    }
    ok(primary_login()->{ticket}, 'alternative role restores primary sign-in eligibility');
    $NATIVE_ENTRIES->{'alice@pve'}->[0]->{enable} = JSON::PP::true;
    $NATIVE_ENTRIES->{'alice@pve'}->[-1]->{enable} = JSON::PP::true;
    $state = call_api('get_mode');
    my $unchanged = JSON::PP->new->canonical->encode($NATIVE_ENTRIES);
    my $cached = PVE::Cluster::cfs_read_file('priv/tfa.cfg');
    for my $failure ('update', 'serializer', 'write') {
        local $NATIVE_UPDATES = 0;
        local $NATIVE_UPDATE_FAIL = $failure eq 'update' ? 2 : 0;
        local $NATIVE_SERIALIZE_FAIL = $failure eq 'serializer' ? 1 : 0;
        local $NATIVE_WRITE_FAIL = $failure eq 'write' ? 1 : 0;
        ok(error_from(sub { call_api('set_mode', {mode => 'alternative', expected_revision => $state->{revision}, password => 'fixture-password'}) }), 'native update/serializer/write failure aborts the transition');
        is(JSON::PP->new->canonical->encode($NATIVE_ENTRIES), $unchanged, 'failure never partially changes authoritative native flags');
        is(JSON::PP->new->canonical->encode($cached->{entries}), $unchanged, 'failed cloned updates never poison the cached native object');
    }
    my $writes_before = $NATIVE_WRITES;
    $state = call_api('set_mode', {mode => 'alternative', expected_revision => $state->{revision}, password => 'fixture-password'});
    is($NATIVE_WRITES, $writes_before + 1, 'disabling multiple native keys is one atomic native write');
    is($state->{enabled_native_key_count}, 0, 'alternative mode disables every own passkey second factor');
    ok($state->{other_factors_enabled}, 'atomic role switch preserves native TOTP and recovery factors');
    is(JSON::PP->new->canonical->encode($cached->{entries}), $unchanged, 'successful clone write also leaves old cached object immutable');
    $state = call_api('get_mode');
    {
        local $NATIVE_WRITE_FAIL_AFTER = 1;
        ok(error_from(sub { call_api('set_mode', {mode => 'two_factor', key_id => 'owned-native-key', expected_revision => $state->{revision}, password => 'fixture-password'}) }), 'ambiguous native writer failure is reported without restoring an entire auth store');
    }
    is(call_api('get_mode')->{mode}, 'two_factor', 'fresh authoritative read resolves an already committed native write');
    $NATIVE_ENTRIES->{'alice@pve'}->[0]->{enable} = JSON::PP::false;
    {
        local $MFA_HOOK = sub { $NATIVE_ENTRIES->{'alice@pve'}->[0]->{enable} = JSON::PP::true; };
        like(error_from(sub { primary_login() }), qr/401/, 'primary gate rereads role after native MFA policy evaluation');
    }
    logged_in('root@pam');
    my $root_mode = call_api('get_mode');
    like(error_from(sub { call_api('set_mode', {mode => 'two_factor', key_id => 'root-native-key', expected_revision => $root_mode->{revision}}) }), qr/401/, 'root mode transition also requires a fresh native password');
    my $root_password_checks = scalar(@PASSWORD_CHECKS);
    is(call_api('set_mode', {mode => 'two_factor', key_id => 'root-native-key', expected_revision => $root_mode->{revision}, password => 'fixture-password'})->{mode},
        'two_factor', 'root can commit the role only after its fresh native password proof');
    is(scalar(@PASSWORD_CHECKS) - $root_password_checks, 1, 'root role mutation invokes the native password plugin despite its ordinary native TFA exception');
    logged_in('alice@pve');
}
{
    local $USER = undef; local $CREDENTIALS = {token => 'SLL-Passkey-Login'};
    my $begin = call_api('login_begin');
    is(length($begin->{nonce}), 43, 'public login returns opaque browser nonce');
    ok(!exists($COMMANDS[-1]->{user}), 'discoverable begin has no caller-supplied username');
}
{
    local $CREDENTIALS = {token => 'missing'};
    like(error_from(sub { call_api('login_begin') }), qr/401 authentication failure/, 'public begin needs non-simple header marker');
    like(error_from(sub { call_api('login_finish', $finish) }), qr/401 authentication failure/, 'public finish needs nonce-shaped header');
}
{
    my $old_binding = PVE::API2::SLLPasskeys::account_binding('alice@pve');
    local $PASSWORD_HASH = '$6$new-salt$' . ('B' x 86);
    local $CORE_BINDING = $old_binding;
    like(error_from(sub { primary_login() }), qr/401 authentication failure/, 'password reset or recreated account rejects old credential binding');
}
my $login = primary_login();
is($login->{username}, 'alice@pve', 'verified core user becomes native user');
ok(exists($login->{cap}) && !exists($login->{NeedTFA}), 'full native capability map only without pending MFA');
is_deeply($TICKETS[-1], ['alice@pve'], 'normal ticket uses native assembler');
is_deeply($MFA_CALLS[-1], ['alice@pve', 'pve', undef, undef], 'native current MFA policy always consulted after primary assertion');
{
    local $MFA = '{"totp":true}';
    my $partial = primary_login();
    ok($partial->{NeedTFA}, 'existing MFA produces native partial login');
    ok(!exists($partial->{cap}), 'partial login has no capability map');
    is_deeply($TICKETS[-1], ['!tfa!{"totp":true}', 'alice@pve'], 'partial ticket is native signed challenge with user AAD');
}
for my $kind ('DISABLED', 'EXPIRED', 'MFA_FAIL') {
    no strict 'refs'; local ${'main::' . $kind} = 1;
    my $tickets = scalar(@TICKETS);
    like(error_from(sub { primary_login() }), qr/401 authentication failure/, "$kind denied generically");
    is(scalar(@TICKETS), $tickets, "$kind never issues a ticket");
}
{
    local $DOMAINS = {ids => {}};
    like(error_from(sub { primary_login() }), qr/401 authentication failure/, 'deleted realm denied');
}
{
    local $DOMAINS = {ids => {pve => {type => 'pve', enable => 0}}};
    like(error_from(sub { primary_login() }), qr/401 authentication failure/, 'explicitly disabled realm denied');
}
{
    local $CORE_USER = 'alice@ldap';
    like(error_from(sub { primary_login() }), qr/401 authentication failure/, 'external realm cannot bypass provider policy');
}
{
    local $CORE_USER = 'alice@pam';
    my $pam = primary_login(); is($pam->{username}, 'alice@pam', 'PAM user allowed after account checks');
    { local $CORE_USER = substr($ENV{PATH}, 0, 0) . 'alice@pam'; ok(tainted($CORE_USER), 'PAM bridge result taint fixture is active'); my $tainted_pam = primary_login(); is($tainted_pam->{username}, 'alice@pam', 'tainted verified PAM identity is safely captured before fixed getent/passwd argv'); }
    for my $locked ('L', 'NP') { local $PAM_STATUS = $locked; like(error_from(sub { primary_login() }), qr/401 authentication failure/, 'locked/no-password Unix account denied'); }
    local $PAM_BAD = 1;
    like(error_from(sub { primary_login() }), qr/401 authentication failure/, 'PAM account expiry/access policy retained');
}
for my $kind ('CORE_FAIL', 'MALFORMED', 'OVERSIZED') {
    no strict 'refs'; local ${'main::' . $kind} = 1;
    like(error_from(sub { primary_login() }), qr/401 authentication failure/, "$kind core result denied generically");
}
open(my $maintenance, '>', "$root/maintenance") or die $!; print {$maintenance} 'active'; close($maintenance); chmod(0600, "$root/maintenance");
ok(call_api('status')->{primary_passkeys}, 'public activation health remains available during maintenance');
like(error_from(sub { call_api('credentials') }), qr/503/, 'management blocked during maintenance');
like(error_from(sub { primary_login() }), qr/401 authentication failure/, 'login blocked during maintenance');
unlink("$root/maintenance");
chmod(0755, $root) or die $!;
like(error_from(sub { call_api('credentials') }), qr/control directory must be private/, 'a readable control directory is rejected before opening a lock');
chmod(0720, $root) or die $!;
like(error_from(sub { call_api('credentials') }), qr/unsafe Makeover control directory/, 'a writable control directory is rejected');
chmod(0700, $root) or die $!;
rename("$root/control.lock", "$root/saved.lock") or die $!;
symlink("$root/saved.lock", "$root/control.lock") or die $!;
like(error_from(sub { call_api('credentials') }), qr/refusing symlink/, 'a symlink cannot replace the private control lock');
unlink("$root/control.lock") or die $!;
link("$root/saved.lock", "$root/control.lock") or die $!;
like(error_from(sub { call_api('credentials') }), qr/unsafe passkey control lock/, 'a hard-linked control lock is rejected');
unlink("$root/control.lock") or die $!;
rename("$root/saved.lock", "$root/control.lock") or die $!;
symlink("$root/control.lock", "$root/maintenance") or die $!;
like(error_from(sub { call_api('credentials') }), qr/refusing symlink/, 'a symlink cannot replace the maintenance marker');
unlink("$root/maintenance") or die $!;
# Actual OS flock regression: independent anonymous login workers may overlap,
# but a credential deletion cannot cross an in-flight login's ticket boundary.
pipe(my $held_read, my $held_write) or die $!;
pipe(my $release_read, my $release_write) or die $!;
my $holder = fork(); die $! if !defined($holder);
if (!$holder) {
    close($held_read); close($release_write); $held_write->autoflush(1);
    PVE::API2::SLLPasskeys::public_operation(sub { print {$held_write} "held\n"; scalar(<$release_read>); return {}; });
    POSIX::_exit(0);
}
close($held_write); close($release_read);
is(scalar(<$held_read>), "held\n", 'public login holds a real shared lock');
pipe(my $shared_read, my $shared_write) or die $!;
my $parallel = fork(); die $! if !defined($parallel);
if (!$parallel) {
    close($shared_read); $shared_write->autoflush(1);
    PVE::API2::SLLPasskeys::public_operation(sub { print {$shared_write} "parallel\n"; return {}; });
    POSIX::_exit(0);
}
close($shared_write);
my $shared_ready = IO::Select->new($shared_read)->can_read(2);
ok($shared_ready, 'another public login enters while the first login is still in flight');
is(scalar(<$shared_read>), "parallel\n", 'parallel shared login completed') if $shared_ready;
pipe(my $secondary_read, my $secondary_write) or die $!;
my $secondary = fork(); die $! if !defined($secondary);
if (!$secondary) {
    close($secondary_read); $secondary_write->autoflush(1);
    my $result = call_api('remove_second_factor', {id => 'owned-native-key', password => 'fixture-password'});
    print {$secondary_write} "native-secondary\n" if ref($result) eq 'HASH' && $result->{removed};
    POSIX::_exit(0);
}
close($secondary_write);
my $secondary_ready = IO::Select->new($secondary_read)->can_read(2);
ok($secondary_ready, 'native secondary removal does not block behind an in-flight shared primary login');
is(scalar(<$secondary_read>), "native-secondary\n", 'native reauthentication route completes under its own shared control guard') if $secondary_ready;
pipe(my $exclusive_read, my $exclusive_write) or die $!;
my $deletion = fork(); die $! if !defined($deletion);
if (!$deletion) {
    close($exclusive_read); $exclusive_write->autoflush(1);
    PVE::API2::SLLPasskeys::guarded_operation(sub { print {$exclusive_write} "delete\n"; return {}; });
    POSIX::_exit(0);
}
close($exclusive_write);
ok(!IO::Select->new($exclusive_read)->can_read(.1), 'exclusive credential deletion waits for the login ticket boundary');
print {$release_write} "release\n"; close($release_write);
my $exclusive_ready = IO::Select->new($exclusive_read)->can_read(2);
ok($exclusive_ready, 'deletion enters after the final in-flight shared login releases');
is(scalar(<$exclusive_read>), "delete\n", 'exclusive operation then completes') if $exclusive_ready;
for my $pid ($holder, $parallel, $secondary, $deletion) { kill('TERM', $pid) if !$exclusive_ready; waitpid($pid, 0); }
close($held_read); close($shared_read); close($secondary_read); close($exclusive_read);

{
    my $native_before = scalar(@SECONDARY_DELETES);
    my $crypto_before = scalar(@COMMANDS);
    for my $id ('other-native-key', 'totp-key', 'recovery-key', 'missing-key') {
        like(error_from(sub { call_api('remove_second_factor', {id => $id, password => 'fixture-password'}) }), qr/401 authentication failure/,
            'secondary removal rejects unowned or non-security-key entries');
    }
    for my $password (undef, 'wrong-password') {
        like(error_from(sub { call_api('remove_second_factor', {id => 'owned-native-key', defined($password) ? (password => $password) : ()}) }),
            qr/401 authentication failure/, 'native secondary removal reauthentication failure is generic');
    }
    { local $CREDENTIALS = {ticket => 'full:alice@pve', token => 'invalid'};
      like(error_from(sub { call_api('remove_second_factor', {id => 'owned-native-key', password => 'fixture-password'}) }), qr/401/, 'secondary removal requires native CSRF'); }
    { local $CREDENTIALS = {ticket => 'half-new', token => 'csrf:alice@pve'};
      like(error_from(sub { call_api('remove_second_factor', {id => 'owned-native-key', password => 'fixture-password'}) }), qr/401/, 'secondary removal rejects incomplete native tickets'); }
    { local $CREDENTIALS = {api_token => 'fixture'};
      like(error_from(sub { call_api('remove_second_factor', {id => 'owned-native-key', password => 'fixture-password'}) }), qr/401/, 'secondary removal rejects API tokens'); }
    { local $DISABLED = 1;
      like(error_from(sub { call_api('remove_second_factor', {id => 'owned-native-key', password => 'fixture-password'}) }), qr/401/, 'disabled account cannot remove native factors'); }
    is(scalar(@SECONDARY_DELETES), $native_before, 'all negative checks leave native credential state unchanged');
    my $removed = call_api('remove_second_factor', {id => 'owned-native-key', password => 'fixture-password'});
    ok(ref($removed) eq 'HASH' && $removed->{removed}, 'owned native security key removal returns its explicit object after native reauthentication');
    is_deeply($SECONDARY_DELETES[-1], {user => 'alice@pve', id => 'owned-native-key', has_password => 1}, 'native deletion receives only the current account and submitted password presence');
    is(scalar(@COMMANDS), $crypto_before, 'native secondary password never enters the Python verifier');
    like(error_from(sub { call_api('remove_second_factor', {id => 'owned-native-key', password => 'fixture-password'}) }), qr/401/, 'repeated secondary removal is denied without another native write');
    is(scalar(@SECONDARY_DELETES), $native_before + 1, 'repeated removal leaves native state unchanged');
    logged_in('root@pam');
    ok(call_api('remove_second_factor', {id => 'root-native-key'})->{removed}, 'native root password exception is preserved for owned U2F removal');
    logged_in('alice@pve');
}

PVE::API2::SLLPasskeys::install_auth_hook();
my $server = bless {}, 'PVE::HTTPServer';
for my $case (['GET', '/sll-passkeys/status', undef], ['POST', '/sll-passkeys/login-begin', 'SLL-Passkey-Login'], ['POST', '/sll-passkeys/login-finish', 'n' x 43]) {
    my ($method, $path, $token) = @$case;
    my $auth = $server->auth_handler($method, $path, undef, $token, undef, '127.0.0.1');
    is($AUTH_CALLS[-1]->[2], '/access/ticket', 'exact public endpoint uses native anonymous initialization');
    is($auth->{token}, $token, 'browser marker/nonce preserved in exposed auth credentials');
}
for my $path ('/sll-passkeys/login-begin/', '/sll-passkeys/login-begin/other', '/sll-passkeys/credentials', '/sll-passkeys/remove-second-factor', '/sll-customs/config', '/access/users') {
    like(error_from(sub { $server->auth_handler('POST', $path, undef, 'SLL-Passkey-Login', undef, '127.0.0.1') }), qr/No ticket/, 'all other paths retain native authentication');
}
like(error_from(sub { $server->auth_handler('GET', '/sll-passkeys/login-begin', undef, 'SLL-Passkey-Login', undef, '127.0.0.1') }), qr/No ticket/, 'wrong public method retains native authentication');
like(error_from(sub { $server->auth_handler('POST', '/sll-passkeys/login-begin', undef, undef, undef, '127.0.0.1') }), qr/401/, 'public form-style request without marker rejected');
like(error_from(sub { $server->auth_handler('POST', '/sll-passkeys/login-finish', undef, 'bad', undef, '127.0.0.1') }), qr/401/, 'public finish missing nonce rejected');
like(error_from(sub { $server->auth_handler('GET', '/sll-passkeys/status', undef, undef, 'token', '127.0.0.1') }), qr/401/, 'API tokens cannot use anonymous hook');
my $audit = join("\n", @AUDIT);
like($audit, qr/successful primary passkey authentication/, 'native success audit event');
like($audit, qr/primary passkey proof verified.*native MFA required/, 'partial MFA audit labels only primary proof');
like($audit, qr/primary passkey enrolled.*user=.*key=/, 'credential enrollment audited by user and metadata hash');
like($audit, qr/primary passkey revoked.*user=.*key=/, 'credential deletion audited');
unlike($audit, qr/fixture-password|fixture-assertion-secret|n{43}|c{32}|NATIVE:|private PAM diagnostic|A{86}|B{86}/, 'audit contains no passwords, proofs, nonces, tickets or internal diagnostics');
done_testing();
