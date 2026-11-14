package SLL::Makeover::Bootstrap;

use strict;
use warnings;

use HTTP::Headers;
use HTTP::Response;
use PVE::AccessControl;
use PVE::Cluster;
use PVE::API2;
use PVE::APIServer::Formatter;
use PVE::API2::SLLCustoms;
use PVE::API2::SLLPasskeys;

our $VERSION = '0.1-beta';

PVE::API2->register_method({
    subclass => 'PVE::API2::SLLCustoms',
    path => 'sll-customs',
});

PVE::API2->register_method({
    subclass => 'PVE::API2::SLLPasskeys',
    path => 'sll-passkeys',
});
PVE::API2::SLLPasskeys::install_auth_hook();

sub protected_page {
    my ($server, $request) = @_;

    my $cookie = $request->header('Cookie') // '';
    my $ticket = PVE::APIServer::Formatter::extract_auth_value(
        $cookie,
        $server->{cookie_name},
    );
    my ($username, undef, $tfa) = $ticket ? eval { PVE::AccessControl::verify_ticket($ticket, 1) } : ();
    my $authenticated = defined($username) && !ref($username) && !defined($tfa) && length($username) && $username !~ /!/;
    if ($authenticated) {
        $authenticated = eval {
            PVE::AccessControl::check_user_enabled(PVE::Cluster::cfs_read_file('user.cfg'), $username);
            1;
        };
    }

    if (!$authenticated) {
        my $headers = HTTP::Headers->new(
            'Cache-Control' => 'no-store, max-age=0',
            'Content-Type' => 'text/plain; charset=utf-8',
            'Content-Security-Policy' => "default-src 'none'; frame-ancestors 'none'",
            'Pragma' => 'no-cache',
            'Referrer-Policy' => 'no-referrer',
            'X-Content-Type-Options' => 'nosniff',
            'X-Frame-Options' => 'DENY',
        );
        return HTTP::Response->new(401, 'Login Required', $headers, "Proxmox login required.\n");
    }

    my $headers = HTTP::Headers->new(
        'Cache-Control' => 'no-store, max-age=0',
        'Location' => '/?sll-customs=1',
        'Pragma' => 'no-cache',
        'Referrer-Policy' => 'same-origin',
        'X-Content-Type-Options' => 'nosniff',
    );
    return HTTP::Response->new(303, 'See Other', $headers, '');
}

if (($ENV{SLL_MAKEOVER_SERVICE} // '') eq 'pveproxy') {
    require PVE::Service::pveproxy;

    my $original_init = PVE::Service::pveproxy->can('init')
        or die "unable to locate PVE::Service::pveproxy::init\n";

    no warnings qw(redefine once);
    *PVE::Service::pveproxy::init = sub {
        my ($self, @args) = @_;
        $original_init->($self, @args);

        my $handler = sub {
            my ($server, $request) = @_;
            return protected_page($server, $request);
        };
        $self->{server_config}->{pages}->{'/SLL-Customs'} = $handler;
        $self->{server_config}->{pages}->{'/SLL-Customs/'} = $handler;
    };
}

1;
