#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""MIG-ALLOW on the installed host (ci.sh --install), as the owner chose it ("A: immer, überall"). SMTP on port 25 through
XCLIENT (allowed only for 127.0.0.1 and only during this test), as a client outside mynetworks with a bad HELO and on a
blocklist (an inline table stands in for the RBL):
- an allowed sender of a domain that does not resolve gets past all of that; another sender of that domain does not;
- an allowed sender to a foreign recipient gets 554: never an open relay;
- a mail of the allowed sender with the test virus EICAR is taken, without the attachment (note, X-eFa-next-Removed), the
  original is kept by efa-cdr; the same mail of another sender is rejected.
Everything is put back afterwards; the outbound block of the host is never touched."""
import email.message
import json
import re
import smtplib
import subprocess
import sys
import time

LISTED = '203.0.113.25'  # TEST-NET-3: outside mynetworks
ALLOWED, OTHER = 'arnold-it@ai.local', 'another@ai.local'
# The test file of EICAR, put together here so no scanner flags this script.
EICAR = ('X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*').encode()
SAVED_LISTS = ('smtpd_authorized_xclient_hosts', 'smtpd_client_restrictions', 'smtpd_helo_restrictions', 'smtpd_sender_restrictions')


def run(*cmd, check=True):
    done = subprocess.run(cmd, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise SystemExit(f'{" ".join(cmd)}: {(done.stdout + done.stderr)[-400:]}')
    return done.stdout.strip()


def session(addr, helo='badhelo'):
    smtp = smtplib.SMTP('127.0.0.1', 25, timeout=60)
    smtp.ehlo('ci.example')
    code, text = smtp.docmd('XCLIENT', f'ADDR={addr} NAME=[UNAVAILABLE] HELO={helo}')
    assert code == 220, (code, text)
    smtp.ehlo(helo)
    return smtp


def rcpt(addr, sender, recipient):
    with session(addr) as smtp:
        code, text = smtp.mail(sender)
        if code >= 400:
            return code, text.decode(errors='replace')
        code, text = smtp.rcpt(recipient)
        smtp.rset()
        return code, text.decode(errors='replace')


def send_virus(addr, sender, recipient, helo='badhelo'):
    """(code, text) of the end of DATA for a mail with the EICAR test file."""
    mail = email.message.EmailMessage()
    mail['From'], mail['To'], mail['Subject'] = sender, recipient, 'eFa-next CI: virus of an allowed sender'
    mail.set_content('Test of the CI.\n')
    mail.add_attachment(EICAR, maintype='application', subtype='octet-stream', filename='eicar.txt')
    with session(addr, helo) as smtp:
        code, text = smtp.mail(sender)
        assert code == 250, (code, text)
        code, text = smtp.rcpt(recipient)
        assert code == 250, (code, text)
        code, text = smtp.data(mail.as_bytes())
        return code, text.decode(errors='replace')


def main():
    with open('/etc/postfix/transport') as f:
        domains = [line.split()[0] for line in f if line.strip() and not line.startswith('#')]
    if not domains:
        print('sender-allow-live: skipped, no relay domain on this host')
        return 0
    if not json.loads(run('/usr/sbin/efactl', 'cdr-status'))['milter_in_chain']:
        print('sender-allow-live: efa-cdr is not in the milter chain: a virus is rejected for everyone, the cut out is not tested')
    local = f'postmaster@{domains[0]}'
    saved = {name: run('postconf', '-h', name) for name in SAVED_LISTS}
    queued = []
    try:
        run('postconf', '-e', 'smtpd_authorized_xclient_hosts = 127.0.0.1')
        run('postconf', '-e', 'smtpd_client_restrictions = ' + ', '.join(item for item in (f'check_client_access inline:{{{LISTED}=REJECT}}',
                                                                                           saved['smtpd_client_restrictions']) if item))
        run('postconf', '-e', 'smtpd_helo_restrictions = ' + ', '.join(item for item in (saved['smtpd_helo_restrictions'], 'reject_non_fqdn_helo_hostname') if item))
        run('postconf', '-e', 'smtpd_sender_restrictions = ' + ', '.join(item for item in (saved['smtpd_sender_restrictions'], 'reject_unknown_sender_domain') if item))
        print(run('/usr/sbin/efactl', 'sender-add', '--list=allow', f'--entries={ALLOWED}', '--comment=CI'))
        run('postfix', 'reload')
        found = {'allowed': rcpt(LISTED, ALLOWED, local), 'other': rcpt(LISTED, OTHER, local), 'relay': rcpt(LISTED, ALLOWED, 'someone@example.net')}
        print(found)
        assert found['allowed'][0] == 250, ('the allowed sender gets past RBL, HELO and DNS', found)
        assert found['other'][0] >= 400, ('another sender of that domain does not', found)
        assert found['relay'][0] == 554 and 'Relay access denied' in found['relay'][1], ('never an open relay', found)
        code, text = send_virus(LISTED, ALLOWED, local)
        print('virus of the allowed sender:', code, text)
        assert code == 250, (code, text)
        qid = re.search(r'queued as (\S+)', text).group(1)
        queued.append(qid)
        time.sleep(3)
        stored = run('journalctl', '-u', 'efa-cdr', '--since', '-5min', '-o', 'cat', check=False)
        assert f'virus removed from=<{ALLOWED}>' in stored and 'parts=eicar.txt' in stored, 'efa-cdr cut the virus out: ' + stored[-400:]
        headers = run('postcat', '-hq', qid, check=False)
        if headers:
            assert 'X-eFa-next-Removed: eicar.txt' in headers, headers
            assert 'EICAR-STANDARD' not in run('postcat', '-bq', qid, check=False), 'the test virus is out of the mail'
        else:
            print('the mail left the queue already: header checked through the journal of efa-cdr')
        # The own network gets past Postfix: here only the virus check of rspamd decides.
        other_code, other_text = send_virus('127.0.0.1', 'ci-virus@efa-next.eu', local, 'mx.ci.example.org')
        print('virus of another sender:', other_code, other_text)
        assert other_code >= 500, ('a virus of another sender is rejected', other_code, other_text)
        print('sender-allow-live: ok')
        return 0
    finally:
        run('/usr/sbin/efactl', 'sender-remove', f'--entries={ALLOWED}', '--confirm=yes', check=False)
        for name, value in saved.items():
            if value:
                run('postconf', '-e', f'{name} = {value}', check=False)
            else:
                run('postconf', '-X', name, check=False)
        run('postfix', 'reload', check=False)
        for qid in queued:
            run('postsuper', '-d', qid, check=False)


if __name__ == '__main__':
    sys.exit(main())
