#!/usr/bin/perl
# Copyright (c) 2018-2023 CentralNic Ltd and contributors. All rights reserved.
# This program is free software; you can redistribute it and/or modify it under
# the same terms as Perl itself.
use Cwd;
use Data::Mirror qw(mirror_fh mirror_json);
use DateTime;
use File::Slurp;
use File::stat;
use Getopt::Long;
use IO::Socket;
use JSON::XS;
use Object::Anon;
use POSIX qw(floor);
use Pod::Usage;
use constant WHOIS_HOST => 'whois.iana.org';
use constant WHOIS_PORT => 43;
use open qw(:utf8);
use utf8;
use strict;

my $VERSION = '0.1';

my $help;
GetOptions('help' => \$help);

pod2usage() if ($help);

my $dir = $ARGV[0] || getcwd();

if (!-e $dir || !-d $dir) {
    printf(STDERR "Error: %s doesn't exist, please create it first\n");
    exit(1);
}

my $json = JSON::XS->new->utf8->pretty->canonical;

my @tlds = map { chomp ; lc } grep { /^[A-Z0-9-]+$/ } mirror_fh('https://data.iana.org/TLD/tlds-alpha-by-domain.txt')->getlines;

my $status = {
    'active'    => 1,
    'removed'   => 1,
    'former'    => 1,
};

my $rdap_servers;
foreach my $service (@{anon(mirror_json('https://data.iana.org/rdap/dns.json'))->services}) {
    my @tlds = @{$service->[0]};
    my @urls = @{$service->[1]};
    my $url = (grep { $_ =~ /^https:/ } @urls, @urls)[0];
    foreach my $tld (@tlds) {
        $rdap_servers->{$tld} = $url;
    }
}

my $gtlds;
foreach my $gtld (@{anon(mirror_json('https://www.icann.org/resources/registries/gtlds/v2/gtlds.json'))->gTLDs}) {
    $gtlds->{$gtld->gTLD} = $gtld;
}

print STDERR "Generating files\n";

my $all = {
  'rdapConformance' => [ 'rdap_level_0' ],
  'domainSearchResults' => [],
};

foreach my $tld (@tlds) {
    my $file = sprintf('%s/%s.txt', $dir, $tld);
    my @data;

    if (-e $file && stat($file)->mtime >= time()-86400) {
        @data = read_file($file);

    } else {
        printf(STDERR "Updating data for .%s\n", uc($tld));

        my $socket = IO::Socket::INET->new(
            'PeerAddr'  => WHOIS_HOST,
            'PeerPort'  => WHOIS_PORT,
            'Type'      => SOCK_STREAM,
            'Proto'     => 'tcp',
            'Timeout'   => 5,
        );
        if (!$socket) {
            warn($@);

        } else {
            $socket->print(sprintf("%s\r\n", $tld));

            @data = $socket->getlines;

            $socket->close;

            if (!write_file($file, @data)) {
                printf(STDERR "Unable to write data to '%s': %s\n", $file, $!);
                exit(1);
            }
        }
    }

    #
    # the first set of contact information we see in the response is the
    # sponsoring organisation (the "registrant" of the TLD)
    #
    my $contact = 'registrant';

    #
    # initialise JSON object
    #
    my $data = {
        'objectClassName'   => 'domain',
        'ldhName'           => $tld,
        'handle'            => $tld,
        'port43'            => WHOIS_HOST,
        'rdapConformance'   => [ 'rdap_level_0' ],
    };

    #
    # we put entity information into this hashref, we need to
    # pre-populate the registrant object
    #
    my $entities = {
        $contact => {
            'objectClassName'   => 'entity',
            'handle'            => sprintf('%s-%s', $tld, $contact),
            'vcardArray'        => empty_vcard_array(),
            'roles'             => [ $contact ]
        },
    };

    my @comments;

    my $url;

    foreach my $line (@data) {
        chomp($line);

        if ($line =~ /^% *(.+)/) {
            #
            # push comment lines into an array for later inclusion
            #
            push(@comments, $1);

        } elsif (length($line) < 1) {
            #
            # ignore empty line
            #
            next;

        } else {
            my ($key, $value) = split(/\: */, $line, 2);

            if ('domain' eq $key || 'domain-ace' eq $key) {
                # discard

            } elsif ('source' eq $key) {
                push(@{$data->{'remarks'}}, {
                    'title' => 'Source',
                    'description' => [ $value ],
                });

            } elsif ('nserver' eq $key) {
                #
                # value consists of hostname followed by one or more IPs
                #
                my ($ns, @ips)    = split(/ /, $value);

                push(@{$data->{'nameservers'}}, {
                    'objectClassName' => 'nameserver',
                    'ldhName' => $ns,
                    'ipAddresses' => {
                        'v4' => [ grep { /\./ } @ips ], # use simplistic regexp to
                        'v6' => [ grep { /:/  } @ips ], # split IPs into families
                    },
                });

            } elsif ('ds-rdata' eq $key) {
                #
                # value is a DS record in presentation format
                #
                my ($tag, $alg, $digestType, $digest) = split(/ /, $value, 4);

                $data->{'secureDNS'}->{'delegationSigned'} = \1;

                push(@{$data->{'secureDNS'}->{'dsData'}}, {
                    'keyTag'        => $tag,
                    'algorithm'     => $alg,
                    'digest'        => $digest,
                    'digestType'    => $digestType,
                });

            } elsif ('status' eq $key) {
                if (!defined($status->{lc($value)})) {
                    printf(STDERR "Unknown status '%s'\n", $value);
                    exit(1);

                } else {
                    push(@{$data->{'status'}}, lc($value));

                }

            } elsif ('created' eq $key) {
                push(@{$data->{'events'}}, {
                    'eventAction' => 'registration',
                    'eventDate' => $value,
                });

            } elsif ('changed' eq $key) {
                push(@{$data->{'events'}}, {
                    'eventAction' => 'last changed',
                    'eventDate' => $value,
                });

            } elsif ('remarks' eq $key) {
                my $remark = {
                    'title' => 'Remark',
                    'description' => [ $value ]
                };

                if ($value =~ /Registration information: (https?:\/\/.+)/i) {
                    $url = $1;

                    $remark->{'links'} = [{
                        'title' => 'URL for registration services',
                        'rel'   => 'related',
                        'href'  => $url,
                    }];
                }

                push(@{$data->{'remarks'}}, $remark);

            } elsif ('contact' eq $key) {
                #
                # signifies the start of a new contact, so change the value of
                # $contact and initialise a new object in $entities
                #
                $contact = $value;
                $entities->{$contact} = {
                    'objectClassName' => 'entity',
                    'handle' => sprintf('%s-%s', $tld, $contact),
                    'vcardArray' => empty_vcard_array(),
                    'roles' => [ $value ]
                };

            } elsif ('name' eq $key) {
                push(@{$entities->{$contact}->{'vcardArray'}->[1]}, [ 'fn', {}, 'text', $value ]);

            } elsif ('organisation' eq $key) {
                push(@{$entities->{$contact}->{'vcardArray'}->[1]}, [ 'org', {}, 'text', $value ]);

            } elsif ('address' eq $key) {
                #
                # look for an existing address node in the vcard
                #
                my $adr = (grep { $_->[0] eq 'adr' } @{$entities->{$contact}->{'vcardArray'}->[1]})[0];

                #
                # create one if not found
                #
                if (!defined($adr)) {
                    $adr = [ 'adr', { 'label' => '' }, 'text', [ '', '', '', '', '', '', '' ] ];
                    push(@{$entities->{$contact}->{'vcardArray'}->[1]}, $adr);
                }

                #
                # append the line to the address
                #
                if (length($adr->[1]->{'label'}) < 1) {
                    $adr->[1]->{'label'} = $value;

                } else {
                    $adr->[1]->{'label'} .= "\n".$value;

                }

            } elsif ('phone' eq $key) {
                push(@{$entities->{$contact}->{'vcardArray'}->[1]}, ['tel', {}, 'text', $value ]);

            } elsif ('fax-no' eq $key) {
                push(@{$entities->{$contact}->{'vcardArray'}->[1]}, ['tel', { 'type' => 'fax' }, 'text', $value ]);

            } elsif ('e-mail' eq $key) {
                push(@{$entities->{$contact}->{'vcardArray'}->[1]}, ['email', {}, 'text', $value ]);

            } elsif ('whois' eq $key) {
                push(@{$data->{'remarks'}}, {
                    'title' => 'Whois Service',
                    'description' => [ sprintf('The port-43 whois service for this TLD is %s.', uc($value || ($gtlds->{$tld} ? sprintf('whois.nic.%s', $tld) : ''))) ]
                });

            } else {
                printf(STDERR "Unknown key '%s'\n", $key);
                exit(1);

            }
        }
    }

    push(@{$data->{'events'}}, {
        'eventAction' => 'last update of RDAP database',
        'eventDate' => DateTime->now->iso8601,
    });

    $data->{'notices'} = [
        {
            'title' => 'About This Service',
            'description' => [
                'Please note that this RDAP service is NOT provided by the IANA.',
                '',
                'For more information, please see https://about.rdap.org',
            ],
        }
    ];

    #
    # insert comments as a notice
    #
    push(@{$data->{'notices'}}, {'title' => 'Comments', 'description' => \@comments }) if (scalar(@comments) > 0);

    #
    # add some links
    #
    $data->{'links'} = [
        {
            'title' => 'Entry for this TLD in the Root Zone Database',
            'rel'   => 'related',
            'href'  => sprintf('https://www.iana.org/domains/root/db/%s.html', $tld),
        },
        {
            'title' => 'About RDAP',
            'rel'   => 'related',
            'href'  => 'https://about.rdap.org',
        }
    ];

    push(@{$data->{'links'}}, {
        'title' => 'URL for registration services',
        'rel'   => 'related',
        'href'  => $url,
    }) if ($url);

    if ($rdap_servers->{$tld}) {
        push(@{$data->{'remarks'}}, {
            'title' => 'RDAP Service',
            'description' => [ sprintf('The RDAP Base URL for this TLD is %s.', $rdap_servers->{$tld}) ],
            'links' => [
                {
                    'rel'   => 'related',
                    'title' => 'RDAP Base URL',
                    'href'  => $rdap_servers->{$tld},
                }
            ],
        });

        push(@{$data->{'links'}}, {
            'title' => 'RDAP Base URL',
            'rel'   => 'related',
            'href'  => $rdap_servers->{$tld},
        }) if ($url);
    }

    if ($gtlds->{$tld}) {
        push(@{$data->{'links'}}, {
            'title' => 'gTLD Registry Agreement',
            'rel'   => 'related',
            'href'  => sprintf('https://www.icann.org/en/registry-agreements/details/%s', $tld),
        });

        push(@{$data->{'remarks'}}, {
            'title' => 'gTLD Application ID',
            'description' => [ $gtlds->{$tld}->applicationId ],
        }) if ($gtlds->{$tld}->applicationId);

        push(@{$data->{'remarks'}}, {
            'title' => 'Specification 13 (Code of Conduct) Exemption',
            'description' => [
                'This TLD has an exemption from Specification 13 of the Registry Agreement.',
                'This usually means that it is a Single Registrant or "brand" TLD.',
            ],
            'links' => [
                {
                    'rel'   => 'related',
                    'title' => 'More information about Specification 13 exemptions',
                    'href'  => 'https://newgtlds.icann.org/en/applicants/agb/base-agreement-contracting/specification-13-applications',
                }
            ],
        }) if ($gtlds->{$tld}->specification13);

        $data->{'unicodeName'} = $gtlds->{$tld}->uLabel if ($gtlds->{$tld}->uLabel);
    }

    #
    # insert entities
    #
    $data->{'entities'} = [map { $entities->{$_} } sort(keys(%{$entities}))];

    #
    # write RDAP object to disk
    #
    my $jfile = sprintf('%s/%s.json', $dir, $tld);

    if (!write_file($jfile, $json->encode($data))) {
        printf(STDERR "Unable to write to '%s': %s\n", $jfile, $!);
        exit(1);
    }

    $all->{'notices'} = $data->{'notices'} unless (defined($all->{'notices'}));
    delete($data->{'notices'});
    delete($data->{'rdapConformance'});

    push(@{$all->{'domainSearchResults'}}, $data);
}

#
# write RDAP object to disk
#
my $jfile = sprintf('%s/_all.json', $dir);

if (!write_file($jfile, $json->encode($all))) {
    printf(STDERR "Unable to write to '%s': %s\n", $jfile, $!);
    exit(1);
}

print STDERR "done\n";

#
# returns an arrayref containing an empty jcard-compliant data structure
#
sub empty_vcard_array { [ 'vcard', [ [ 'version', {}, 'text', '4.0' ] ] ] }

__END__

=pod

=head1 NAME

C<rootrdap.pl> - a script to generate a set of RDAP responses from the IANA root zone database.

=head1 DESCRIPTION

As of writing, the Internet Assigned Numbers Authority (IANA) provides a port-43 service for the
root zone database (the list of top-level domains), but does not provide an RDAP service.

This script scrapes data from the IANA whois service and generates RDAP responses for each TLD.

The RDAP responses are written to disk in a directory which can then be exposed through a web
server.

An example of an RDAP service which provides access to this data may be found at
L<https://root.rdap.org>, for example:

=over

=item * L<https://root.rdap.org/domain/xyz>

=back

=head1 USAGE

    rootrdap.pl DIRECTORY

C<DIRECTORY> is the location on disk where the files should be written. C<rootrdap.pl> will write
its working files to this directory as well as the finished .json files.

If C<DIRECTORY> is not provided, the current directory is used.

=head1 COPYRIGHT

Copyright (c) 2018-2023 CentralNic Ltd and contributors. All rights reserved.

=head1 LICENSE

Copyright (c) 2018-2023 CentralNic Ltd and contributors. All rights reserved.
This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=cut
