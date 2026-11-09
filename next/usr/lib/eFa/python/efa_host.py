# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""The own name of the host, one value for reports, headers, the cluster and the login labels.

The name the setup gave the host: myhostname of Postfix, read from main.cf (no postconf run), else the name of the kernel.
Never the full name of the resolver (socket module): it takes the first name of the address in /etc/hosts or asks DNS, so a leftover line there (an old
name on 127.0.0.1) or a slow DNS changes or stops it.
"""
import os
import re
import socket


def own_hostname(etc='/etc'):
    try:
        with open(os.path.join(etc, 'postfix', 'main.cf'), encoding='utf-8') as f:
            for line in f:
                found = re.match(r'^\s*myhostname\s*=\s*([A-Za-z0-9.-]+)\s*$', line)
                if found:
                    return found.group(1).lower()
    except OSError:
        pass
    return socket.gethostname().lower()


if __name__ == '__main__':
    import sys
    import tempfile
    if '--self-test' in sys.argv:
        with tempfile.TemporaryDirectory() as folder:
            os.makedirs(os.path.join(folder, 'postfix'))
            with open(os.path.join(folder, 'postfix', 'main.cf'), 'w') as f:
                f.write('# myhostname = old.example\nmyhostname = MX1.example.org\nmydomain = example.org\n')
            assert own_hostname(folder) == 'mx1.example.org'
            with open(os.path.join(folder, 'postfix', 'main.cf'), 'w') as f:
                f.write('myhostname = $mydomain\n')
            assert own_hostname(folder) == socket.gethostname().lower(), 'a value with $ is no name: the kernel name'
            assert own_hostname(os.path.join(folder, 'none')) == socket.gethostname().lower()
        print('self-test ok')
    else:
        print(own_hostname())
