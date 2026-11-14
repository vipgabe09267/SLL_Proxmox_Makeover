package PVE::API2::SLLPasskeys;

use strict;
use warnings;
use Authen::PAM qw(:constants);
use JSON::PP;
use Digest::SHA qw(sha256_hex);
use Fcntl qw(:flock O_WRONLY O_CREAT O_NOFOLLOW);
use File::Basename qw(dirname);
use URI;
use PVE::AccessControl;
use PVE::API2::TFA;
use PVE::Auth::Plugin;
use PVE::Cluster;
use PVE::Exception qw(raise);
use PVE::RESTHandler;
use PVE::RPCEnvironment;
use PVE::SafeSyslog;
use PVE::Tools;
use base qw(PVE::RESTHandler);

our $VERSION = '0.1-beta';
our $AUTH_HOOK_INSTALLED = 0;
my $CORE = '/usr/local/libexec/proxmox-makeover/passkeys.py';
my $LOCK = '/var/lib/proxmox-makeover/control.lock';
my $MAINTENANCE = '/var/lib/proxmox-makeover/maintenance.json';
my $JSON = JSON::PP->new->utf8->canonical->allow_nonref(0)->max_depth(20);
my $STATUS_CACHE;

sub authentication_failure { raise("authentication failure\n", code => 401); }
sub audit_failure {
    my ($remote) = @_;
    $remote = '' if !defined($remote) || ref($remote);
    $remote =~ s/[\x00-\x1f\x7f]/?/g;
    $remote = substr($remote, 0, 255);
    PVE::SafeSyslog::syslog('warning', 'primary passkey authentication failed; client=%s', $remote);
}
sub audit_credential {
    my ($action, $user, $id) = @_;
    $id = 'unavailable' if !defined($id) || ref($id) || $id !~ /\A[0-9a-f]{64}\z/;
    PVE::SafeSyslog::syslog('notice', 'primary passkey %s; user=%s key=%s', $action, $user, $id);
}
sub public_operation {
    my ($code) = @_;
    my $result = eval { guarded_operation($code, 1) };
    if ($@) { eval { audit_failure(PVE::RPCEnvironment::get()->get_client_ip()); }; authentication_failure(); }
    return $result;
}
sub safe_path {
    my ($path) = @_;
    my $current = '';
    for my $part (grep { length($_) } split(m{/}, $path)) {
        $current .= "/$part";
        die "refusing symlink in passkey control path\n" if -l $current;
    }
}
sub ensure_control_directory {
    my $directory = dirname($LOCK);
    my $current = '';
    for my $part (grep { length($_) } split(m{/}, $directory)) {
        $current .= "/$part";
        if (!lstat($current)) {
            mkdir($current, 0700) or die "cannot create private Makeover control directory\n";
        }
        my @info = lstat($current);
        die "unsafe Makeover control directory\n"
            if !@info || !-d _ || -l _ || $info[4] != 0 || ($info[2] & 0022);
        die "Makeover control directory must be private\n"
            if $current eq $directory && ($info[2] & 0777) != 0700;
    }
}
sub guarded_operation {
    my ($code, $shared) = @_;
    ensure_control_directory();
    safe_path($LOCK);
    sysopen(my $lock, $LOCK, O_WRONLY | O_CREAT | O_NOFOLLOW, 0600) or die "cannot open passkey control lock\n";
    my @info = stat($lock);
    die "unsafe passkey control lock\n" if !@info || !-f $lock || $info[3] != 1 || $info[4] != 0 || ($info[2] & 0777) != 0600;
    flock($lock, $shared ? LOCK_SH : LOCK_EX) or die "cannot lock passkey controls\n";
    safe_path($MAINTENANCE);
    if (-e $MAINTENANCE) {
        my @st = lstat($MAINTENANCE);
        die "unsafe Makeover maintenance marker\n" if !@st || !-f _ || $st[3] != 1 || $st[4] != 0 || ($st[2] & 0777) != 0600;
        raise('Makeover is being updated; retry shortly.', code => 503);
    }
    return $code->();
}
sub register_guarded {
    my ($specification, $shared) = @_;
    my $handler = $specification->{code};
    $specification->{code} = sub { my @arguments = @_; return guarded_operation(sub { $handler->(@arguments) }, $shared); };
    __PACKAGE__->register_method($specification);
}
sub auth_credentials {
    my $credentials = PVE::RPCEnvironment::get()->get_credentials();
    return ref($credentials) eq 'HASH' ? $credentials : {};
}
sub interactive_user {
    my ($write) = @_;
    my $rpcenv = PVE::RPCEnvironment::get();
    my $user = $rpcenv->get_user() // '';
    my $credentials = auth_credentials();
    die "a complete interactive Proxmox login is required\n" if !$user || $user =~ /!/ || $credentials->{api_token};
    my ($verified, undef, $tfa) = PVE::AccessControl::verify_ticket($credentials->{ticket} // '', 1);
    die "a complete interactive Proxmox login is required\n" if !defined($verified) || ref($verified)
        || defined($tfa) || $verified ne $user;
    PVE::AccessControl::verify_csrf_prevention_token($user, $credentials->{token} // '') if $write;
    return $user;
}
sub trusted_rp {
    my $dc = PVE::Cluster::cfs_read_file('datacenter.cfg');
    my $web = $dc->{webauthn};
    die "configure native WebAuthn with a trusted HTTPS origin before using login passkeys\n" if ref($web) ne 'HASH';
    my $id = $web->{id};
    die "invalid native WebAuthn RP ID\n" if !defined($id) || ref($id) || length($id) > 253
        || $id !~ /\A[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\z/;
    $id = lc($id);
    die "invalid native WebAuthn RP ID\n" if grep { length($_) > 63 || $_ !~ /\A[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\z/ } split(/\./, $id, -1);
    my $origin = $web->{origin};
    die "native WebAuthn needs an explicit HTTPS origin\n" if !defined($origin) || ref($origin)
        || length($origin) > 512 || $origin =~ /[\s\x00-\x1f\x7f\\]/;
    my $uri = URI->new($origin);
    die "invalid native WebAuthn HTTPS origin\n" if lc($uri->scheme // '') ne 'https' || defined($uri->userinfo)
        || !defined($uri->host) || $uri->host !~ /\A[A-Za-z0-9.-]+\z/
        || defined($uri->query) || defined($uri->fragment) || ($uri->path // '') !~ /\A\/?\z/;
    my $host = lc($uri->host);
    my $port = $uri->port;
    die "invalid native WebAuthn HTTPS port\n" if !defined($port) || "$port" !~ /\A[0-9]+\z/ || $port < 1 || $port > 65535;
    die "native WebAuthn RP ID does not match the configured origin\n" if $host ne $id && $host !~ /\.\Q$id\E\z/;
    my $name = $web->{rp} // 'Proxmox VE';
    die "invalid native WebAuthn relying-party name\n" if ref($name) || !length($name) || length($name) > 128 || $name =~ /[\x00-\x1f\x7f]/;
    return {id => $id, name => "$name", origin => 'https://' . $host . ($port == 443 ? '' : ":$port")};
}
sub local_user {
    my ($user) = @_;
    die "API tokens cannot use login passkeys\n" if !defined($user) || ref($user) || $user =~ /[!\x00-\x1f\x7f]/;
    ($user) = PVE::Auth::Plugin::verify_username($user);
    $user = PVE::AccessControl::lookup_username($user);
    my (undef, $ruid, $realm) = PVE::Auth::Plugin::verify_username($user);
    PVE::RPCEnvironment::get()->check_user_enabled($user);
    PVE::Cluster::cfs_update();
    PVE::AccessControl::check_user_enabled(PVE::Cluster::cfs_read_file('user.cfg'), $user);
    my $domains = PVE::Cluster::cfs_read_file('domains.cfg');
    my $config = $domains->{ids}->{$realm};
    die "the authentication realm is unavailable\n" if ref($config) ne 'HASH';
    die "login passkeys support the local PVE and PAM realms only\n"
        if !(($realm eq 'pve' && ($config->{type} // '') eq 'pve') || ($realm eq 'pam' && ($config->{type} // '') eq 'pam'));
    # Current PVE local realms have no enable option. Fail closed if one is
    # introduced by a future version or local policy and explicitly disabled.
    die "the authentication realm is disabled\n" if exists($config->{enable}) && !$config->{enable};
    die "the authentication realm is disabled\n" if $config->{disable};
    return ($user, $ruid, $realm, $config);
}
sub check_pam_password_state {
    my ($username) = @_;
    my $status = '';
    PVE::Tools::run_command(['/usr/bin/passwd', '-S', '--', $username], timeout => 10,
        outfunc => sub { die "invalid PAM account status\n" if length($status) + length($_[0]) > 1024; $status .= $_[0] . "\n"; },
        errfunc => sub {});
    my ($account, $state) = $status =~ /\A([^\s]+)\s+([A-Z]+)(?:\s|\z)/;
    die "PAM account password is locked or unavailable\n" if !defined($account) || $account ne $username || ($state // '') ne 'P';
}
sub check_pam_account {
    my ($username) = @_;
    my $client = PVE::RPCEnvironment::get()->get_client_ip();
    check_pam_password_state($username);
    # Preserve native PAM account restrictions and isolate SIGCHLD interaction
    # in the same way as the shipped PVE PAM password plugin. No password is
    # supplied here: the verified UV passkey replaces that primary proof only.
    PVE::Tools::run_fork(sub {
        my $pam = Authen::PAM->new('proxmox-ve-auth', $username, sub { return PAM_CONV_ERR(); });
        die "PAM account initialization failed\n" if !ref($pam);
        $pam->pam_set_item(PAM_RHOST(), $client) if defined($client) && length($client);
        die "PAM account is unavailable\n" if $pam->pam_acct_mgmt(0) != PAM_SUCCESS();
        $pam = 0;
        return 1;
    });
}
sub pam_identity {
    my ($username) = @_;
    my @entry = getpwnam($username);
    die "local PAM identity is unavailable\n" if !@entry || !defined($entry[2]) || !defined($entry[3]);
    return ($entry[2], $entry[3]);
}
sub account_binding {
    my ($user) = @_;
    my ($canonical, $ruid, $realm) = local_user($user);
    my ($hash, @identity);
    if ($realm eq 'pve') {
        my $shadow = PVE::Cluster::cfs_read_file('priv/shadow.cfg');
        $hash = $shadow->{users}->{$ruid}->{shadow};
    } else {
        @identity = pam_identity($ruid);
        my $record = '';
        PVE::Tools::run_command(['/usr/bin/getent', '-s', 'files', 'shadow', '--', $ruid], timeout => 10,
            outfunc => sub { die "local PAM account record is oversized\n" if length($record) + length($_[0]) > 8192; $record .= $_[0] . "\n"; },
            errfunc => sub {});
        my @lines = split(/\n/, $record);
        die "local PAM password record is unavailable\n" if @lines != 1 || $lines[0] =~ /[\x00-\x1f\x7f]/;
        my ($name, $value) = split(/:/, $lines[0]);
        die "local PAM password record is unavailable\n" if !defined($name) || $name ne $ruid;
        $hash = $value;
    }
    die "account password record is unavailable\n" if !defined($hash) || ref($hash)
        || length($hash) < 13 || length($hash) > 1024 || $hash !~ /\A[A-Za-z0-9.\/\$=,+_-]+\z/;
    # Never persist or send the native password record itself to the verifier.
    # Changing/resetting a password deliberately invalidates old login passkeys.
    return sha256_hex($JSON->encode(['SLL primary passkey account generation v1', $canonical, $realm, @identity, $hash]));
}
sub same_binding {
    my ($left, $right) = @_;
    return 0 if !defined($left) || !defined($right) || ref($left) || ref($right)
        || $left !~ /\A[0-9a-f]{64}\z/ || $right !~ /\A[0-9a-f]{64}\z/;
    my $different = 0;
    $different |= ord(substr($left, $_, 1)) ^ ord(substr($right, $_, 1)) for 0 .. 63;
    return $different == 0;
}
sub verify_primary_password {
    my ($user, $password) = @_;
    die "your current Proxmox password is required\n" if !defined($password) || ref($password) || !length($password) || length($password) > 1024;
    my ($canonical, $ruid, $realm, $config) = local_user($user);
    my $before = account_binding($canonical);
    my $plugin = PVE::Auth::Plugin->lookup($config->{type});
    $plugin->authenticate_user($config, $realm, $ruid, $password);
    my $after = account_binding($canonical);
    if (!same_binding($before, $after)) {
        die "account generation changed during password verification\n" if $realm ne 'pve';
        # Native PVE authentication may upgrade a legacy password hash. Verify
        # the supplied password again against the fresh record; the old proof
        # alone must never authorize enrollment into a different generation.
        $before = $after;
        $plugin->authenticate_user($config, $realm, $ruid, $password);
        die "account generation changed during password verification\n"
            if !same_binding($before, account_binding($canonical));
    }
    # The native plugin includes account management for PAM. Registration never
    # sends this password to the Python process, command arguments, or storage.
    return {user => $canonical, binding => $before};
}
sub checked_core {
    my $path = '';
    for my $part (grep { length($_) } split(m{/}, $CORE)) {
        $path .= "/$part";
        die "unsafe passkey implementation path\n" if -l $path;
        next if !-e $path;
        my @st = stat($path);
        die "untrusted passkey implementation path\n" if !@st || $st[4] != 0 || ($st[2] & 0022);
    }
    die "passkey implementation is unavailable\n" if !-f $CORE;
    $CORE =~ m{\A(/[A-Za-z0-9_./-]+)\z} or die "unsafe passkey implementation path\n";
    return $1;
}
sub bridge {
    my ($input) = @_;
    my $encoded = $JSON->encode($input);
    die "passkey request exceeds its size limit\n" if length($encoded) > 96 * 1024;
    my $output = '';
    my $ok = eval {
        PVE::Tools::run_command(['/usr/bin/python3', '-I', checked_core()], input => $encoded, timeout => 20,
            outfunc => sub {
                die "passkey response exceeds its size limit\n" if length($output) + length($_[0]) > 128 * 1024;
                $output .= $_[0] . "\n";
            }, errfunc => sub {});
        1;
    };
    die "passkey operation failed\n" if !$ok;
    my $result = eval { $JSON->decode($output) };
    die "passkey operation returned an invalid result\n" if $@ || ref($result) ne 'HASH';
    return $result;
}
sub client {
    my $value = PVE::RPCEnvironment::get()->get_client_ip() // 'local';
    die "invalid client address\n" if ref($value) || length($value) > 255 || $value =~ /[\x00-\x1f\x7f]/;
    return "$value";
}
sub ceremony {
    my ($value) = @_;
    die "invalid passkey ceremony\n" if !defined($value) || ref($value) || $value !~ /\A[0-9a-f]{32}\z/;
    return "$value";
}
sub credential_response {
    my ($value) = @_;
    die "invalid passkey response\n" if !defined($value) || ref($value) || length($value) > 65536;
    my $response = eval { $JSON->decode($value) };
    die "invalid passkey response\n" if $@ || ref($response) ne 'HASH';
    return $response;
}
sub description {
    my ($value) = @_;
    die "a passkey description is required\n" if !defined($value) || ref($value) || !length($value) || length($value) > 64 || $value =~ /[\x00-\x1f\x7f]/;
    $value =~ s/\A\s+|\s+\z//g;
    die "a passkey description is required\n" if !length($value);
    return "$value";
}
sub native_key_metadata {
    my ($user, $config) = @_;
    my $entries = $config->api_list_user_tfa($user);
    die "invalid native factor metadata\n" if ref($entries) ne 'ARRAY' || @$entries > 512;
    my @all = sort { $a->{id} cmp $b->{id} } map {
        die "invalid native factor metadata\n" if ref($_) ne 'HASH' || !defined($_->{id}) || ref($_->{id}) || !defined($_->{type}) || ref($_->{type});
        {id => "$_->{id}", type => "$_->{type}", description => "" . ($_->{description} // ''),
            created => 0 + ($_->{created} // 0), enable => !exists($_->{enable}) || $_->{enable} ? JSON::PP::true : JSON::PP::false}
    } @$entries;
    return (\@all, [grep { $_->{type} =~ /\A(?:webauthn|u2f)\z/ } @all]);
}
sub native_mode_snapshot {
    my ($user, $config) = @_;
    PVE::Cluster::cfs_update();
    my $users = PVE::Cluster::cfs_read_file('user.cfg');
    PVE::AccessControl::check_user_enabled($users, $user);
    my (undef, undef, $realm) = PVE::Auth::Plugin::verify_username($user);
    my $domains = PVE::Cluster::cfs_read_file('domains.cfg');
    my $domain = $domains->{ids}->{$realm} // {};
    my $legacy = $users->{users}->{$user}->{keys};
    my $legacy_unsupported = defined($legacy) && length($legacy) && $legacy !~ /\Ax(?:!.*)?\z/;
    $config //= PVE::Cluster::cfs_read_file('priv/tfa.cfg');
    my ($all, $keys) = native_key_metadata($user, $config);
    my $enabled = scalar(grep { $_->{enable} } @$keys);
    my $reason = $realm !~ /\A(?:pve|pam)\z/ || ($domain->{type} // '') ne $realm ?
        'Passkey mode changes support local PVE and PAM accounts only.' :
        $domain->{tfa} ? 'The realm enforces two-factor authentication. Manage that policy in native Proxmox settings.' :
        $legacy_unsupported ? 'Migrate legacy factor settings through native Proxmox before changing passkey mode.' : undef;
    my $binding = eval { account_binding($user) };
    $reason //= 'The current native password record is unavailable for fresh verification.' if $@ || !$binding;
    my $realm_policy = {id => $realm, type => $domain->{type} // '',
        enable => exists($domain->{enable}) ? ($domain->{enable} ? JSON::PP::true : JSON::PP::false) : JSON::PP::true,
        disable => $domain->{disable} ? JSON::PP::true : JSON::PP::false,
        has_tfa => $domain->{tfa} ? JSON::PP::true : JSON::PP::false};
    my $legacy_kind = !defined($legacy) || !length($legacy) ? 'none' : $legacy eq 'x' ? 'native' : $legacy =~ /\Ax!/ ? 'native-marked' : 'unsupported';
    my $revision = sha256_hex($JSON->encode({user => $user, entries => $all,
        realm => $realm_policy, legacy => $legacy_kind,
        enabled => $users->{users}->{$user}->{enable} // 0, expire => $users->{users}->{$user}->{expire} // 0}));
    return {user => $user, binding => $binding, config => $config, public => {
        mode => $enabled ? 'two_factor' : 'alternative', revision => $revision,
        can_change => $reason ? JSON::PP::false : JSON::PP::true, reason => $reason,
        native_keys => $keys, native_key_count => scalar(@$keys), enabled_native_key_count => 0 + $enabled,
        other_factors_enabled => scalar(grep { $_->{enable} && $_->{type} !~ /\A(?:webauthn|u2f)\z/ } @$all) ? JSON::PP::true : JSON::PP::false,
    }};
}
sub native_mode_payload {
    my ($snapshot) = @_;
    my $view = $snapshot->{public};
    my $count = eval {
        die "native generation unavailable\n" if !$snapshot->{binding};
        my $list = bridge({op => 'list', rp => trusted_rp(), user => $snapshot->{user}, binding => $snapshot->{binding}});
        die "invalid primary credential metadata\n" if ref($list->{credentials}) ne 'ARRAY';
        scalar(@{$list->{credentials}});
    };
    $view->{primary_key_count} = $@ ? undef : 0 + $count;
    $view->{primary_ready} = $view->{mode} eq 'alternative' && defined($view->{primary_key_count}) && $view->{primary_key_count} > 0 ? JSON::PP::true : JSON::PP::false;
    return $view;
}
sub require_primary_mode {
    my ($user) = @_;
    PVE::Cluster::cfs_update();
    my (undef, $keys) = native_key_metadata($user, PVE::Cluster::cfs_read_file('priv/tfa.cfg'));
    die "native security keys are configured as a second factor\n" if grep { $_->{enable} } @$keys;
}
sub native_login {
    my ($user, $binding) = @_;
    my ($canonical, $ruid, $realm) = local_user($user);
    die "account generation changed\n" if !same_binding(account_binding($canonical), $binding);
    require_primary_mode($canonical);
    check_pam_account($ruid) if $realm eq 'pam';
    my $mfa = PVE::AccessControl::authenticate_2nd_new($canonical, $realm, undef, undef);
    # Recheck revocation/expiry after crypto and native MFA challenge creation.
    local_user($canonical);
    die "account generation changed\n" if !same_binding(account_binding($canonical), $binding);
    require_primary_mode($canonical);
    my $result = {
        username => $canonical,
        CSRFPreventionToken => PVE::AccessControl::assemble_csrf_prevention_token($canonical),
    };
    if (defined($mfa)) {
        die "invalid native second-factor challenge\n" if ref($mfa) || length($mfa) > 65536;
        $result->{NeedTFA} = JSON::PP::true;
        $result->{ticket} = PVE::AccessControl::assemble_ticket("!tfa!$mfa", $canonical);
        PVE::Cluster::log_msg('info', 'root@pam', "primary passkey proof verified for user '$canonical'; native MFA required");
        # Deliberately no full user ticket or capability map before native MFA.
    } else {
        $result->{ticket} = PVE::AccessControl::assemble_ticket($canonical);
        $result->{cap} = PVE::RPCEnvironment::get()->compute_api_permission($canonical);
        PVE::Cluster::log_msg('info', 'root@pam', "successful primary passkey authentication for user '$canonical'");
    }
    return $result;
}

# Only these anonymous routes are added to the native authentication gate.
# Delegate all native initialization and every other path to the original code.
sub install_auth_hook {
    return if $AUTH_HOOK_INSTALLED;
    require PVE::HTTPServer;
    my $original = PVE::HTTPServer->can('auth_handler') or die "native authentication handler is unavailable\n";
    no warnings qw(redefine once);
    *PVE::HTTPServer::auth_handler = sub {
        my ($self, $method, $path, $ticket, $token, $api_token, $peer) = @_;
        my $public_status = $method eq 'GET' && $path eq '/sll-passkeys/status';
        my $public_begin = $method eq 'POST' && $path eq '/sll-passkeys/login-begin';
        my $public_finish = $method eq 'POST' && $path eq '/sll-passkeys/login-finish';
        if ($public_status || $public_begin || $public_finish) {
            if ($api_token || ($public_begin && ($token // '') ne 'SLL-Passkey-Login')
                || ($public_finish && ($token // '') !~ /\A[A-Za-z0-9_-]{43}\z/)) {
                eval { audit_failure($peer); };
                authentication_failure();
            }
            # /access/ticket is already native-public for GET/POST. Reuse only
            # its unauthenticated RPC initialization; routing remains the real
            # original /sll-passkeys path and protected native root proxy.
            return $original->($self, $method, '/access/ticket', $ticket, $token, $api_token, $peer);
        }
        return $original->(@_);
    };
    $AUTH_HOOK_INSTALLED = 1;
}

my $CEREMONY = {type => 'string', pattern => '^[0-9a-f]{32}$', minLength => 32, maxLength => 32};
my $RESPONSE = {type => 'string', minLength => 2, maxLength => 65536};
register_guarded({
    name => 'index', path => '', method => 'GET', protected => 1, allowtoken => 0, expose_credentials => 1,
    permissions => {user => 'all'}, parameters => {additionalProperties => 0, properties => {}},
    description => 'Primary login passkeys. Native passwords and TFA remain available.',
    returns => {type => 'array'}, code => sub { interactive_user(0); return [map { {subdir => $_} } qw(status mode credentials register-begin register-finish login-begin login-finish remove-second-factor)]; },
});
__PACKAGE__->register_method({
    name => 'status', path => 'status', method => 'GET', protected => 1, allowtoken => 0,
    permissions => {user => 'world'}, parameters => {additionalProperties => 0, properties => {}},
    description => 'Non-secret primary passkey capability and configured relying party.', returns => {type => 'object'},
    code => sub {
        my $rp = eval { trusted_rp() };
        my $supported = 0;
        if ($rp) {
            my @st = stat($CORE);
            my $key = $JSON->encode($rp) . ':' . ($st[9] // 0) . ':' . ($st[7] // 0);
            if (!$STATUS_CACHE || $STATUS_CACHE->{key} ne $key || $STATUS_CACHE->{time} + 30 < time()) {
                my $status = eval { bridge({op => 'status', rp => $rp}) };
                $STATUS_CACHE = {key => $key, time => time(), supported => $status && $status->{supported} ? 1 : 0};
            }
            $supported = $STATUS_CACHE->{supported};
        }
        my $result = {version => $VERSION, primary_passkeys => JSON::PP::true, secondary_removal => JSON::PP::true, per_user_mode => JSON::PP::true,
            supported => $supported ? JSON::PP::true : JSON::PP::false, rp => $rp};
        $result->{reason} = !$rp ? 'Configure WebAuthn in Datacenter -> Options with this node trusted HTTPS origin before adding login passkeys.' :
            'The login passkey service is unavailable. Ask the administrator to check the installation.' if !$supported;
        return $result;
    },
});
register_guarded({
    name => 'get_mode', path => 'mode', method => 'GET', protected => 1, allowtoken => 0, expose_credentials => 1,
    permissions => {user => 'all'}, parameters => {additionalProperties => 0, properties => {}},
    description => 'Read the current account passkey role from native factor flags.', returns => {type => 'object'},
    code => sub { return native_mode_payload(native_mode_snapshot(interactive_user(0))); },
}, 1);
register_guarded({
    name => 'set_mode', path => 'mode', method => 'POST', protected => 1, allowtoken => 0, expose_credentials => 1,
    permissions => {user => 'all'}, parameters => {additionalProperties => 0, properties => {
        mode => {type => 'string', enum => ['alternative', 'two_factor']},
        expected_revision => {type => 'string', pattern => '^[0-9a-f]{64}$', minLength => 64, maxLength => 64},
        password => {type => 'string', minLength => 1, maxLength => 1024},
        key_id => {type => 'string', optional => 1, minLength => 1, maxLength => 128, pattern => '^[A-Za-z0-9._:-]+$'},
    }}, description => 'Set an owned passkey role using one native locked factor update.', returns => {type => 'object'},
    code => sub {
        my ($param) = @_;
        my $user = interactive_user(1);
        my $proof = eval { verify_primary_password($user, $param->{password}) };
        authentication_failure() if $@ || !$proof || $proof->{user} ne $user;
        PVE::AccessControl::lock_tfa_config(sub {
            my $snapshot = native_mode_snapshot($user);
            raise('Passkey mode cannot be changed for this account.', code => 400) if !$snapshot->{public}->{can_change};
            raise('Passkey settings changed; reload and try again.', code => 409)
                if $snapshot->{public}->{revision} ne $param->{expected_revision};
            authentication_failure() if !same_binding($proof->{binding}, $snapshot->{binding});
            my $keys = $snapshot->{public}->{native_keys};
            my @targets = $param->{mode} eq 'two_factor' ? grep { $_->{id} eq ($param->{key_id} // '') } @$keys : grep { $_->{enable} } @$keys;
            raise('Enroll and explicitly select an owned native security key first.', code => 400) if $param->{mode} eq 'two_factor' && @targets != 1;
            my $next = PVE::AccessControl::parse_priv_tfa_config('priv/tfa.cfg', $snapshot->{config}->write());
            $next->api_update_tfa_entry($user, $_->{id}, undef, $param->{mode} eq 'two_factor' ? 1 : 0) for @targets;
            authentication_failure() if !same_binding($proof->{binding}, account_binding($user));
            my $fresh = native_mode_snapshot($user);
            raise('Passkey settings changed; reload and try again.', code => 409)
                if $fresh->{public}->{revision} ne $param->{expected_revision};
            authentication_failure() if !same_binding($proof->{binding}, $fresh->{binding});
            PVE::Cluster::cfs_write_file('priv/tfa.cfg', $next) if @targets;
        });
        return native_mode_payload(native_mode_snapshot($user));
    },
}, 1);
register_guarded({
    name => 'remove_second_factor', path => 'remove-second-factor', method => 'POST', protected => 1, allowtoken => 0, expose_credentials => 1,
    permissions => {user => 'all'}, parameters => {additionalProperties => 0, properties => {
        id => {type => 'string', minLength => 1, maxLength => 128, pattern => '^[A-Za-z0-9._:-]+$'},
        password => {%{$PVE::API2::TFA::OPTIONAL_PASSWORD_SCHEMA}},
    }}, description => 'Remove only an owned native WebAuthn or U2F second factor through native reauthentication.', returns => {type => 'object'},
    code => sub {
        my ($param) = @_;
        my $removed = eval {
            my $user = interactive_user(1);
            PVE::RPCEnvironment::get()->check_user_enabled($user);
            PVE::Cluster::cfs_update();
            PVE::AccessControl::check_user_enabled(PVE::Cluster::cfs_read_file('user.cfg'), $user);
            my $entries = PVE::API2::TFA->list_user_tfa({userid => $user});
            die "unavailable native security key\n" if ref($entries) ne 'ARRAY' || !grep {
                ($_->{id} // '') eq $param->{id} && ($_->{type} // '') =~ /\A(?:webauthn|u2f)\z/
            } @$entries;
            PVE::API2::TFA->delete_tfa({userid => $user, id => $param->{id},
                (exists($param->{password}) ? (password => $param->{password}) : ())});
            1;
        };
        authentication_failure() if !$removed || $@;
        return {removed => JSON::PP::true};
    },
}, 1);
register_guarded({
    name => 'credentials', path => 'credentials', method => 'GET', protected => 1, allowtoken => 0, expose_credentials => 1,
    permissions => {user => 'all'}, parameters => {additionalProperties => 0, properties => {}},
    description => 'List only the current user primary login passkeys.', returns => {type => 'object'},
    code => sub { my ($user) = local_user(interactive_user(0)); return bridge({op => 'list', rp => trusted_rp(), user => $user, binding => account_binding($user)}); },
});
register_guarded({
    name => 'register_begin', path => 'register-begin', method => 'POST', protected => 1, allowtoken => 0, expose_credentials => 1,
    permissions => {user => 'all'}, parameters => {additionalProperties => 0, properties => {
        password => {type => 'string', minLength => 1, maxLength => 1024}, description => {type => 'string', minLength => 1, maxLength => 64},
    }}, description => 'Begin primary passkey registration after current-account password verification.', returns => {type => 'object'},
    code => sub {
        my ($param) = @_;
        my $interactive = interactive_user(1);
        my $proof = eval { verify_primary_password($interactive, $param->{password}) };
        authentication_failure() if $@;
        return bridge({op => 'register_begin', rp => trusted_rp(), user => $proof->{user}, binding => $proof->{binding}, description => description($param->{description}), client => client()});
    },
});
register_guarded({
    name => 'register_finish', path => 'register-finish', method => 'POST', protected => 1, allowtoken => 0, expose_credentials => 1,
    permissions => {user => 'all'}, parameters => {additionalProperties => 0, properties => {ceremony => $CEREMONY, response => $RESPONSE}},
    description => 'Complete the current user primary passkey registration.', returns => {type => 'object'},
    code => sub {
        my ($param) = @_;
        my ($user) = local_user(interactive_user(1));
        my $result = bridge({op => 'register_finish', rp => trusted_rp(), user => $user, binding => account_binding($user), ceremony => ceremony($param->{ceremony}), response => credential_response($param->{response}), client => client()});
        audit_credential('enrolled', $user, $result->{id});
        return $result;
    },
});
register_guarded({
    name => 'delete', path => 'credentials/{id}', method => 'DELETE', protected => 1, allowtoken => 0, expose_credentials => 1,
    permissions => {user => 'all'}, parameters => {additionalProperties => 0, properties => {id => {type => 'string', pattern => '^[0-9a-f]{64}$', minLength => 64, maxLength => 64}}},
    description => 'Remove only a primary passkey belonging to the current user.', returns => {type => 'object'},
    code => sub {
        my ($param) = @_;
        my ($user) = local_user(interactive_user(1));
        die "invalid passkey id\n" if !defined($param->{id}) || ref($param->{id}) || $param->{id} !~ /\A[0-9a-f]{64}\z/;
        my $result = bridge({op => 'delete', rp => trusted_rp(), user => $user, binding => account_binding($user), id => $param->{id}});
        audit_credential('revoked', $user, $param->{id});
        return $result;
    },
});
__PACKAGE__->register_method({
    name => 'login_begin', path => 'login-begin', method => 'POST', protected => 1, allowtoken => 0, expose_credentials => 1,
    permissions => {user => 'world'}, parameters => {additionalProperties => 0, properties => {}},
    description => 'Begin discoverable UV-required primary passkey login.', returns => {type => 'object'},
    code => sub {
        return public_operation(sub {
            authentication_failure() if auth_credentials()->{api_token} || (auth_credentials()->{token} // '') ne 'SLL-Passkey-Login';
            return bridge({op => 'login_begin', rp => trusted_rp(), client => client()});
        });
    },
});
__PACKAGE__->register_method({
    name => 'login_finish', path => 'login-finish', method => 'POST', protected => 1, allowtoken => 0, expose_credentials => 1,
    permissions => {user => 'world'}, parameters => {additionalProperties => 0, properties => {ceremony => $CEREMONY, response => $RESPONSE}},
    description => 'Verify a primary passkey, then retain native TFA requirements before full login.', returns => {type => 'object'},
    code => sub {
        my ($param) = @_;
        return public_operation(sub {
            my $auth = auth_credentials();
            authentication_failure() if $auth->{api_token} || ($auth->{token} // '') !~ /\A[A-Za-z0-9_-]{43}\z/;
            my $result = bridge({op => 'login_finish', rp => trusted_rp(), ceremony => ceremony($param->{ceremony}),
                response => credential_response($param->{response}), nonce => $auth->{token}, client => client()});
            return native_login($result->{user}, $result->{binding});
        });
    },
});
1;
