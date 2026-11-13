#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""S36 on the installed host (ci.sh --install): while the release upgrade holds new mail (421), an allowed sender must get the
421 too, also after the heal of a package update ran (sender-skip-heal places the allow lookups). After the way back the
allowed sender is taken again and smtpd_client_restrictions is the list of before. SMTP on port 25 through XCLIENT (allowed
only for 127.0.0.1 and only during this test); the state of the release upgrade goes to a folder of the test, never the real
one. Everything is put back afterwards."""
import os
import smtplib
import subprocess
import sys
import tempfile

CLIENT = '203.0.113.26'  # TEST-NET-3: outside mynetworks
ALLOWED = 'ci-allowed@ai.local'


def run(*cmd, check=True):
    done = subprocess.run(cmd, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise SystemExit(f'{" ".join(cmd)}: {(done.stdout + done.stderr)[-400:]}')
    return done.stdout.strip()


def rcpt(sender, recipient):
    with smtplib.SMTP('127.0.0.1', 25, timeout=60) as smtp:
        smtp.ehlo('ci.example')
        code, text = smtp.docmd('XCLIENT', f'ADDR={CLIENT} NAME=[UNAVAILABLE] HELO=mail.ci.example')
        assert code == 220, (code, text)
        smtp.ehlo('mail.ci.example')
        code, text = smtp.mail(sender)
        if code < 400:
            code, text = smtp.rcpt(recipient)
        if code == 421:
            return code, text.decode(errors='replace')  # Postfix closes the connection after a 421: no RSET, no QUIT
        smtp.rset()
        return code, text.decode(errors='replace')


def main():
    with open('/etc/postfix/transport') as f:
        domains = [line.split()[0] for line in f if line.strip() and not line.startswith('#')]
    if not domains:
        print('maintenance-cidr-live: skipped, no relay domain on this host')
        return 0
    local = f'postmaster@{domains[0]}'
    os.environ['EFA_RU_DIR'] = tempfile.mkdtemp(prefix='efa-ci-ru-')
    sys.path.insert(0, '/usr/lib/eFa/python')
    import efactl_main as efactl  # noqa: E402  the installed efactl, with the state of the release upgrade in the test folder
    saved_xclient = run('postconf', '-h', 'smtpd_authorized_xclient_hosts')
    state = {}
    try:
        run('postconf', '-e', 'smtpd_authorized_xclient_hosts = 127.0.0.1')
        run('/usr/sbin/efactl', 'sender-add', '--list=allow', f'--entries={ALLOWED}', '--comment=CI S36')
        # The list as the heal leaves it on this host: the list of before the upgrade.
        run('/usr/sbin/efactl', 'sender-skip-heal')
        run('postfix', 'reload')
        before = run('postconf', '-h', 'smtpd_client_restrictions')
        open_code = rcpt(ALLOWED, local)
        assert open_code[0] == 250, ('the allowed sender is taken before the test', open_code)
        efactl._ru_mail_stop(state)
        # The heal of a package update (efa-next-setup runs it), as on a production host during the upgrade.
        run('/usr/sbin/efactl', 'sender-skip-heal')
        run('postfix', 'reload')
        held = run('postconf', '-h', 'smtpd_client_restrictions')
        first = efactl.restriction_items(held)[0]
        assert efactl._ru_item(first), ('the maintenance map stays first after the heal', held)
        blocked = rcpt(ALLOWED, local)
        print('allowed sender during maintenance:', blocked)
        assert blocked[0] == 421, ('S36: an allowed sender gets 421 while the upgrade holds mail', blocked)
        efactl._ru_mail_start(state)
        after = run('postconf', '-h', 'smtpd_client_restrictions')
        assert efactl.restriction_items(after) == efactl.restriction_items(before), ('the list of before comes back', before, after)
        again = rcpt(ALLOWED, local)
        assert again[0] == 250, ('the allowed sender is taken again', again)
        print('maintenance-cidr-live: ok')
        return 0
    finally:
        if 'client_restrictions' in state:
            efactl._ru_mail_start(state)
        run('/usr/sbin/efactl', 'sender-remove', f'--entries={ALLOWED}', '--confirm=yes', check=False)
        if saved_xclient:
            run('postconf', '-e', f'smtpd_authorized_xclient_hosts = {saved_xclient}', check=False)
        else:
            run('postconf', '-X', 'smtpd_authorized_xclient_hosts', check=False)
        run('postfix', 'reload', check=False)


if __name__ == '__main__':
    sys.exit(main())
