# NAME

`rootrdap.pl` - a script to generate a set of RDAP responses from the IANA root zone database.

# DESCRIPTION

As of writing, the Internet Assigned Numbers Authority (IANA) provides a port-43 service for the
root zone database (the list of top-level domains), but does not provide an RDAP service.

This script scrapes data from the IANA whois service and generates RDAP responses for each TLD.

The RDAP responses are written to disk in a directory which can then be exposed through a web
server.

An example of an RDAP service which provides access to this data may be found at
[https://root.rdap.org](https://root.rdap.org), for example:

- [https://root.rdap.org/domain/xyz](https://root.rdap.org/domain/xyz)

# USAGE

    rootrdap.pl DIRECTORY

`DIRECTORY` is the location on disk where the files should be written. `rootrdap.pl` will write
its working files to this directory as well as the finished .json files.

If `DIRECTORY` is not provided, the current directory is used.

# COPYRIGHT

Copyright (c) 2018-2023 CentralNic Ltd and contributors. All rights reserved.

# LICENSE

Copyright (c) 2018-2023 CentralNic Ltd and contributors. All rights reserved.
This program is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.
