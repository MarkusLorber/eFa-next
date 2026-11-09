#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Live test of the mail paths on an installed host, over 127.0.0.1:25 (scripts/live_test.sh runs it as root).

    live_mail.py DOMAIN RUN_ID

DOMAIN is a local test domain of this host. Nothing leaves the host: live_test.sh sets defer_transports for the time of the
test, so every accepted mail stays in the queue; at the end every mail of this run (sender efa-live-RUN_ID@DOMAIN) is deleted.
Prints one line per path, "ok" or "FAILED (...)", and exits 1 when one failed.
"""
import json
import smtplib
import subprocess
import sys
import time
from email.message import EmailMessage

# The standard test patterns, built at run time so that this file is no test pattern itself.
GTUBE = 'XJS*C4JDBQADN1.NSBN3*2IDNEN*' + 'GTUBE-STANDARD-ANTI-UBE-TEST-EMAIL*C.34X'
EICAR = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$' + 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'


def queue():
    done = subprocess.run(['postqueue', '-j'], capture_output=True, text=True, timeout=30)
    return [json.loads(line) for line in done.stdout.splitlines() if line.strip()]


def mine(sender):
    return [item for item in queue() if item.get('sender') == sender]


def send(sender, rcpt, subject, body='A test of eFa-next.', attachment=None):
    """The SMTP answer: (code, text) of the end of DATA, or of the refusal."""
    message = EmailMessage()
    message['From'], message['To'], message['Subject'] = sender, rcpt, subject
    message.set_content(body)
    if attachment:
        message.add_attachment(attachment.encode(), maintype='application', subtype='octet-stream', filename='eicar.com')
    try:
        with smtplib.SMTP('127.0.0.1', 25, timeout=60) as smtp:
            smtp.ehlo('efa-live-test.invalid')
            smtp.sendmail(sender, [rcpt], message.as_bytes())
            return 250, 'accepted'
    except smtplib.SMTPResponseException as err:
        return err.smtp_code, err.smtp_error.decode(errors='replace')
    except smtplib.SMTPRecipientsRefused as err:
        code, text = list(err.recipients.values())[0]
        return code, text.decode(errors='replace')


def wait_for(sender, test, seconds=60):
    for _ in range(seconds):
        found = [item for item in mine(sender) if test(item)]
        if found:
            return found
        time.sleep(1)
    return []


def main():
    domain, run = sys.argv[1].lower(), sys.argv[2]
    sender, rcpt, external = f'efa-live-{run}@{domain}', f'efa-live-rcpt-{run}@{domain}', f'efa-live-{run}@example.net'
    results = {}
    try:
        code, text = send(sender, rcpt, f'efa-live {run} clean')
        results['inbound clean'] = 'ok' if code == 250 and wait_for(sender, lambda item: item.get('queue_name') in ('active', 'deferred', 'incoming')) \
            else f'FAILED ({code} {text[:120]})'
        code, text = send(sender, rcpt, f'efa-live {run} spam', body=GTUBE)
        held = wait_for(sender, lambda item: item.get('queue_name') == 'hold', 90)
        results['spam (GTUBE)'] = 'ok (rejected)' if code >= 500 else ('ok (quarantine)' if held else f'FAILED (accepted, not held: {code} {text[:120]})')
        code, text = send(sender, rcpt, f'efa-live {run} virus', attachment=EICAR)
        results['virus (EICAR)'] = 'ok (rejected)' if code >= 500 else (
            'ok (quarantine)' if len(wait_for(sender, lambda item: item.get('queue_name') == 'hold', 90)) >= 2 else f'FAILED (accepted: {code} {text[:120]})')
        held = [item['queue_id'] for item in mine(sender) if item.get('queue_name') == 'hold']
        how = 'held by the filter'
        if not held:
            # The host rejects spam and viruses instead of holding them: the clean mail of the run (it waits in the queue) goes
            # on hold by hand, so the quarantine of eFa-next (list, release) is tested without changing a setting. The scoring
            # into hold is not tested then, and the line says so.
            waiting = [item['queue_id'] for item in mine(sender)]
            if waiting:
                subprocess.run(['postsuper', '-h', waiting[0]], capture_output=True, timeout=30)
                held = [item['queue_id'] for item in wait_for(sender, lambda item: item['queue_id'] == waiting[0] and item.get('queue_name') == 'hold', 10)]
                how = 'put on hold with postsuper -h: the filter rejects spam and viruses on this host'
        if held:
            listed = json.loads(subprocess.run(['efactl', 'quarantine-list'], capture_output=True, text=True, timeout=60).stdout or '{}')
            results['quarantine list'] = (f'ok ({how})' if held[0] in [item['id'] for item in listed.get('quarantine', [])]
                                          else 'FAILED (not listed)')
            released = subprocess.run(['efactl', 'quarantine-release', f'--id={held[0]}'], capture_output=True, text=True, timeout=60)
            results['release'] = 'ok' if released.returncode == 0 and not wait_for(
                sender, lambda item: item['queue_id'] == held[0] and item.get('queue_name') == 'hold', 5) else f'FAILED ({released.stderr.strip()[:120]})'
        else:
            results['quarantine list'] = results['release'] = 'FAILED (no mail of the run could be held)'
        code, text = send(sender, external, f'efa-live {run} outbound')
        results['outbound (queue only)'] = 'ok' if code == 250 and wait_for(
            sender, lambda item: any(r.get('address') == external for r in item.get('recipients', []))) else f'FAILED ({code} {text[:120]})'
    finally:
        # Every mail of this run goes, held or deferred: none of them is ever delivered.
        for item in mine(sender):
            subprocess.run(['postsuper', '-d', item['queue_id']], capture_output=True, timeout=30)
        results['queue clean'] = 'ok' if not mine(sender) else 'FAILED (mails of the run left in the queue)'
    for name, result in results.items():
        print(f'mail {name}: {result}')
    return 0 if all(not result.startswith('FAILED') for result in results.values()) else 1


if __name__ == '__main__':
    sys.exit(main())
