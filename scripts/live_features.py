#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Live test of the mail features on an installed host: one real mail per feature over port 25, one check per feature
(scripts/live_test.sh runs it as root, step features, inside the lock of ci.sh).

    live_features.py DOMAIN RUN_ID

DOMAIN is a local test domain of this host. Incoming mail comes in through XCLIENT as a client outside the own networks
(TEST-NET-1), so rspamd and the milters see it as mail from outside; outgoing mail comes from 127.0.0.1 to example.net.
Nothing leaves the host: live_test.sh sets defer_transports and allows XCLIENT for 127.0.0.1 only for the time of the test,
every mail of this run is deleted at the end. A feature that is off is switched on for its check and switched off again
afterwards; a feature whose setting the test cannot put back exactly is SKIPPED, never changed. Prints one line per feature,
"ok", "FAILED (...)" or "SKIPPED (...)", and exits 1 when one failed.
"""
import email.message
import glob
import hashlib
import json
import re
import smtplib
import subprocess
import sys
import time
import urllib.request

OUTSIDE = '192.0.2.25'  # TEST-NET-1: never one of the own networks, never local for rspamd
EFACTL = '/usr/sbin/efactl'
HISTORY_URL = 'http://127.0.0.1:11334/history'
DKIM_DIR = '/etc/rspamd/dkim'
TEST_IBAN = 'DE89370400440532013000'  # the well-known example IBAN of the German banks, valid check digits


class Skip(Exception):
    """The feature cannot be tested on this host; the reason is the text."""


def efactl(command, **options):
    """Runs efactl as root; returns its JSON answer, raises RuntimeError with its message when it fails."""
    done = subprocess.run([EFACTL, command] + [f'--{key}={value}' for key, value in options.items()],
                          capture_output=True, text=True, timeout=300)
    if done.returncode != 0:
        raise RuntimeError(f'efactl {command}: {(done.stderr or done.stdout).strip()[-200:]}')
    try:
        return json.loads(done.stdout or '{}')
    except ValueError:
        return {}


def queue():
    done = subprocess.run(['postqueue', '-j'], capture_output=True, text=True, timeout=30)
    return [json.loads(line) for line in done.stdout.splitlines() if line.strip()]


def symbols_known():
    try:
        done = subprocess.run(['rspamc', 'counters', '-j'], capture_output=True, text=True, timeout=30)
        return {item['symbol'] for item in json.loads(done.stdout)}
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired):
        return set()


def wait_symbol(symbol, seconds=60):
    """After a setting changed: wait until rspamd has the symbol of the feature loaded."""
    for _ in range(seconds):
        if symbol in symbols_known():
            return True
        time.sleep(1)
    return False


class Run:
    def __init__(self, domain, run):
        self.domain, self.run = domain, run
        self.sender = f'efa-live-{run}@{domain}'
        self.rcpt = f'efa-live-rcpt-{run}@{domain}'
        self.external = f'efa-live-{run}@example.net'
        self.count = 0

    def message(self, subject, body='A test of eFa-next.', html=None, from_header=None, headers=None, attachment=None):
        self.count += 1
        mail = email.message.EmailMessage()
        mail['From'] = from_header or self.sender
        mail['To'], mail['Subject'] = self.rcpt, f'efa-live {self.run} {subject}'
        mail['Message-ID'] = f'<efa-live-{self.run}-{self.count}@{self.domain}>'
        for name, value in (headers or {}).items():
            mail[name] = value
        mail.set_content(body)
        if html:
            mail.add_alternative(html, subtype='html')
        if attachment:
            name, content = attachment
            mail.add_attachment(content, maintype='application', subtype='octet-stream', filename=name)
        return mail

    def send(self, mail, outbound=False):
        """(code, text, queue id or None). Incoming over XCLIENT as a client outside, outgoing from 127.0.0.1 to example.net."""
        rcpt = self.external if outbound else self.rcpt
        if outbound:
            mail.replace_header('To', rcpt)
        try:
            with smtplib.SMTP('127.0.0.1', 25, timeout=120) as smtp:
                smtp.ehlo('efa-live-test.invalid')
                if not outbound:
                    code, text = smtp.docmd('XCLIENT', f'ADDR={OUTSIDE} NAME=mail.efa-live.example HELO=mail.efa-live.example')
                    if code != 220:
                        return code, f'XCLIENT refused: {text.decode(errors="replace")}', None
                    smtp.ehlo('mail.efa-live.example')
                code, text = smtp.mail(self.sender)
                if code >= 400:
                    return code, text.decode(errors='replace'), None
                code, text = smtp.rcpt(rcpt)
                if code >= 400:
                    return code, text.decode(errors='replace'), None
                code, text = smtp.data(mail.as_bytes())
                text = text.decode(errors='replace')
                found = re.search(r'queued as (\S+)', text)
                return code, text, found.group(1) if found else None
        except (OSError, smtplib.SMTPException) as err:
            return 0, str(err), None

    def mid(self, mail):
        return str(mail['Message-ID']).strip('<>')

    def symbols(self, mail, seconds=60):
        """The symbols rspamd gave this mail, from its history (found by the Message-ID); None if it is not there."""
        wanted = self.mid(mail)
        for _ in range(seconds):
            try:
                rows = json.loads(urllib.request.urlopen(HISTORY_URL, timeout=10).read()).get('rows', [])
            except (OSError, ValueError, AttributeError):
                rows = []
            for row in rows:
                if str(row.get('message-id', '')).strip('<>') == wanted:
                    found = row.get('symbols') or {}
                    return set(found) if isinstance(found, (dict, list)) else set()
            time.sleep(1)
        return None

    def headers(self, qid, seconds=30):
        """The headers of a queued mail of this run, after all milters; '' when it is not in the queue."""
        for _ in range(seconds):
            done = subprocess.run(['postcat', '-hq', qid], capture_output=True, text=True, timeout=30)
            if done.returncode == 0 and done.stdout.strip():
                return done.stdout
            time.sleep(1)
        return ''

    def body(self, qid):
        return subprocess.run(['postcat', '-bq', qid], capture_output=True, text=True, timeout=30).stdout

    def cleanup(self):
        # Every sender of the run: efa-live-<run>@ and the own one of a check (efa-live-bec-<run>@).
        ours = lambda item: bool(re.fullmatch(rf'efa-live(?:-[a-z]+)?-{self.run}@{re.escape(self.domain)}', item.get('sender') or ''))
        for item in queue():
            if ours(item):
                subprocess.run(['postsuper', '-d', item['queue_id']], capture_output=True, timeout=30)
        return not any(ours(item) for item in queue())


def accepted(code, text, qid):
    if code != 250 or not qid:
        raise AssertionError(f'not accepted: {code} {text[:120]}')


# Each check: (name, function). A function returns the text after "ok", raises Skip, or raises AssertionError/RuntimeError.

def check_bec_vip(r, undo):
    state = efactl('bec-status')
    name = f'Efa Live Chef {r.run}'
    if not state.get('enabled'):
        efactl('bec-set', mode='on')
        undo.append(lambda: efactl('bec-set', mode='off'))
    efactl('bec-vip-set', action='add', name=name, address=f'chef-{r.run}@{r.domain}')
    undo.append(lambda: efactl('bec-vip-set', action='remove', name=name))
    assert wait_symbol('EFA_BEC_VIP_NAME'), 'rspamd did not load the BEC module'
    # bec-vip-set reloads rspamd with the new list; the symbol is there before the workers have it: a new mail every 5 seconds.
    for _ in range(12):
        mail = r.message('bec', from_header=f'"{name}" <{r.sender}>', body='Please pay the invoice today.')
        code, text, _qid = r.send(mail)
        found = r.symbols(mail)
        assert found is not None, f'not in the history of rspamd ({code} {text[:80]})'
        if 'EFA_BEC_VIP_NAME' in found:
            return f'EFA_BEC_VIP_NAME, SMTP {code}'
        time.sleep(5)
    raise AssertionError(f'EFA_BEC_VIP_NAME missing after a minute, rspamd gave {sorted(found)}')


def check_attachment_executable(r, undo):
    state = efactl('attachment-status')
    # With the endings on reject, rspamd's own MIME_BAD_EXTENSION (it finds the program by its content too) reaches the reject
    # score first and rspamd checks no further symbol: the endings on mark for the time of the check, programs on reject.
    efactl('attachment-set', mode='on', action='mark', executables='reject')
    keep = {key: state[key] for key in ('action', 'encrypted', 'macros', 'names', 'executables') if state.get(key)}
    undo.append(lambda: efactl('attachment-set', mode='on' if state.get('enabled') else 'off', **keep))
    state = {**state, 'executables': 'reject'}
    assert wait_symbol('EFA_EXECUTABLE'), 'rspamd did not load the attachment module'
    # A program by its content (MZ) behind a harmless ending. attachment-set reloads rspamd with the new weights: a new mail
    # every 5 seconds until the workers have them.
    for _ in range(12):
        mail = r.message('executable', attachment=('report.dat', b'MZ\x90\x00' + b'\x00' * 60 + b'efa-live'))
        code, text, _qid = r.send(mail)
        found = r.symbols(mail)
        assert found is not None, f'not in the history of rspamd ({code} {text[:80]})'
        if 'EFA_EXECUTABLE' in found:
            break
        time.sleep(5)
    assert 'EFA_EXECUTABLE' in found, f'EFA_EXECUTABLE missing after a minute, rspamd gave {sorted(found)}'
    if state.get('executables', 'reject') == 'reject' and code < 500:
        raise AssertionError(f'EFA_EXECUTABLE set, but the mail was not rejected: {code} {text[:80]}')
    return f'EFA_EXECUTABLE, SMTP {code}'


def check_graymail(r, undo):
    state = efactl('graymail-status')
    efactl('graymail-set', mode='on', default='mark')
    undo.append(lambda: efactl('graymail-set', mode='on' if state.get('enabled') else 'off', default=state.get('default') or 'deliver'))
    assert wait_symbol('EFA_GRAYMAIL'), 'rspamd did not load the graymail module'
    mail = r.message('newsletter', body='Our news of this month.',
                     headers={'List-Unsubscribe': f'<mailto:unsubscribe-{r.run}@{r.domain}>', 'Precedence': 'bulk'})
    code, text, qid = r.send(mail)
    found = r.symbols(mail)
    assert found is not None and 'EFA_GRAYMAIL' in found, f'EFA_GRAYMAIL missing ({code} {text[:80]}): {sorted(found or [])[:12]}'
    accepted(code, text, qid)
    assert 'X-eFa-Graymail: yes' in r.headers(qid), 'marked, but the header X-eFa-Graymail is not in the mail'
    return 'EFA_GRAYMAIL, header X-eFa-Graymail'


def check_own_hash(r, undo):
    content = f'efa-live own block {r.run}'.encode()
    digest = hashlib.sha256(content).hexdigest()
    efactl('own-hash-set', action='add', sha256=digest, name=f'efa-live {r.run}', scope='all')
    undo.append(lambda: efactl('own-hash-set', action='remove', sha256=digest, scope='all'))
    assert wait_symbol('EFA_OWN_HASH'), 'rspamd did not load the own block list'
    time.sleep(3)  # the list itself is read on the reload that loaded the module
    mail = r.message('own hash', attachment=('blocked.bin', content))
    code, text, _qid = r.send(mail)
    found = r.symbols(mail)
    assert found is not None and 'EFA_OWN_HASH' in found, f'EFA_OWN_HASH missing ({code} {text[:80]}): {sorted(found or [])[:12]}'
    assert code >= 500, f'on the own block list, but not rejected: {code} {text[:80]}'
    return f'EFA_OWN_HASH, rejected ({code})'


def check_applications(r, undo):
    rules = {row['domain']: row for row in efactl('application-status').get('domains', [])}
    if r.domain in rules:
        raise Skip(f'{r.domain} has its own choice for applications; it is not changed for the test')
    efactl('application-set', domain=r.domain, mode='list', allowed=f'jobs-{r.run}@{r.domain}')
    undo.append(lambda: efactl('application-set', domain=r.domain, mode='inherit'))
    assert wait_symbol('EFA_APPLICATION'), 'rspamd did not load the applications module'
    time.sleep(3)
    mail = r.message('Bewerbung als Techniker', body='Anbei meine Bewerbungsunterlagen.', attachment=('lebenslauf.pdf', b'%PDF-1.4 efa-live'))
    code, text, _qid = r.send(mail)
    found = r.symbols(mail)
    assert found is not None and 'EFA_APPLICATION' in found, f'EFA_APPLICATION missing ({code} {text[:80]}): {sorted(found or [])[:12]}'
    assert code >= 500, f'an application to an address that takes none, but not rejected: {code} {text[:80]}'
    return f'EFA_APPLICATION, rejected ({code})'


def check_applications_all(r, undo):
    """The rule for all domains (6.0.0.6): its local parts count at the domain of the recipient; another address is refused."""
    rules = {row['domain']: row for row in efactl('application-status').get('domains', [])}
    if '*' in rules or r.domain in rules:
        raise Skip('a rule for all domains or for the test domain is set already; it is not changed for the test')
    efactl('application-set', domain='*', mode='list', allowed=f'jobs-{r.run}')
    undo.append(lambda: efactl('application-set', domain='*', mode='inherit'))
    assert wait_symbol('EFA_APPLICATION'), 'rspamd did not load the applications module'
    time.sleep(3)
    mail = r.message('Bewerbung als Techniker', body='Anbei meine Bewerbungsunterlagen.', attachment=('lebenslauf.pdf', b'%PDF-1.4 efa-live'))
    code, text, _qid = r.send(mail)
    assert code >= 500, f'all domains: an application to an address not listed, but not rejected: {code} {text[:80]}'
    efactl('application-set', domain='*', mode='list', allowed=r.rcpt.split('@')[0])
    time.sleep(5)
    mail = r.message('Bewerbung als Technikerin', body='Anbei meine Bewerbungsunterlagen.', attachment=('lebenslauf.pdf', b'%PDF-1.4 efa-live'))
    code, text, qid = r.send(mail)
    accepted(code, text, qid)
    return f'not listed rejected, listed local part accepted ({qid})'


def content_check(r, undo, setting, status, set_on, set_off, mail, done_text):
    """A feature of the content milter (efa-cdr): on for the check, the mail in the queue carries its X-eFa-CDR note."""
    before = efactl(status)
    if not before.get('enabled', before.get('all')):
        try:
            efactl(setting, **set_on)
        except RuntimeError as err:
            raise Skip(str(err)[-160:])
        undo.append(lambda: efactl(setting, **set_off))
    time.sleep(3)  # the milter reads its settings on the next mail; Postfix reloaded when it went into the chain
    code, text, qid = r.send(mail)
    accepted(code, text, qid)
    headers = r.headers(qid)
    note = next((line for line in headers.splitlines() if line.lower().startswith('x-efa-cdr:')), '')
    assert done_text in note, f'X-eFa-CDR has no "{done_text}": {note[:160] or "no X-eFa-CDR header"}'
    return qid


def check_banner(r, undo):
    mail = r.message('banner', body='Hello from outside.')
    content_check(r, undo, 'banner-set', 'banner-status', {'mode': 'on'}, {'mode': 'off'}, mail, 'warning banner added')
    return 'X-eFa-CDR: warning banner added'


def check_links(r, undo):
    url = f'https://efa-live-{r.run}.example.org/page'
    mail = r.message('links', body=f'Look here: {url}')
    qid = content_check(r, undo, 'links-set', 'links-status', {'mode': 'on'}, {'mode': 'off'}, mail, 'links go over the link check')
    body = r.body(qid)
    assert url not in body and '/l/' in body, 'noted, but the link in the body is still the original one'
    return 'link goes over /l/'


def check_tracking(r, undo):
    html = (f'<p>News</p><a href="https://shop.example.org/item?id=7&utm_source=efa-live-{r.run}&fbclid=x">item</a>'
            '<img src="https://pixel.mailchimp.com/open.gif" width="1" height="1">')
    mail = r.message('tracking', body='News', html=html)
    qid = content_check(r, undo, 'tracking-set', 'tracking-status', {'mode': 'on'}, {'mode': 'off'}, mail, 'tracking removed')
    body = r.body(qid)
    assert f'utm_source=efa-live-{r.run}' not in body and 'pixel.mailchimp.com' not in body, 'noted, but the parameter or pixel is still there'
    return 'pixel and utm_/fbclid gone'


def check_dlp(r, undo):
    before = efactl('dlp-status')
    if before.get('iban', 'off') != 'off':
        wanted = before['iban']
    else:
        efactl('dlp-set', iban='log')
        undo.append(lambda: efactl('dlp-set', iban='off'))
        wanted = 'log'
    if wanted not in ('log', 'hold'):
        raise Skip(f'IBANs are set to {wanted} here; the test needs log or hold')
    assert efactl('dlp-status').get('milter_in_chain'), 'DLP is on, but efa-outbound is not in the milter chain of Postfix'
    time.sleep(3)
    mail = r.message('dlp', body=f'Please pay to {TEST_IBAN} today.')
    code, text, qid = r.send(mail, outbound=True)
    accepted(code, text, qid)
    headers = r.headers(qid)
    assert re.search(rf'^X-eFa-DLP: {wanted}: .*iban', headers, re.M | re.I), 'no X-eFa-DLP header with iban on the outgoing mail'
    return f'X-eFa-DLP {wanted}: iban'


def check_header_privacy(r, undo):
    before = efactl('header-privacy-status')
    if not before.get('all'):
        efactl('header-privacy-set', action='add', scope='all')
        undo.append(lambda: efactl('header-privacy-set', action='remove', scope='all'))
    time.sleep(3)
    mail = r.message('privacy', headers={'X-Mailer': f'efa-live-mailer {r.run}', 'X-Originating-IP': '[10.1.2.3]'})
    code, text, qid = r.send(mail, outbound=True)
    accepted(code, text, qid)
    headers = r.headers(qid)
    assert headers, 'the outgoing mail is not in the queue'
    left = [name for name in ('X-Mailer', 'X-Originating-IP') if re.search(rf'^{name}:\s*\S', headers, re.M | re.I)]
    assert not left, f'still in the outgoing mail: {", ".join(left)}'
    return 'X-Mailer and X-Originating-IP gone'


def check_dkim(r, _undo):
    if not glob.glob(f'{DKIM_DIR}/{r.domain}.*') and not glob.glob(f'{DKIM_DIR}/*{r.domain}*'):
        raise Skip(f'no DKIM key for {r.domain} on this host')
    mail = r.message('dkim')
    code, text, qid = r.send(mail, outbound=True)
    accepted(code, text, qid)
    headers = r.headers(qid)
    signature = re.search(r'^DKIM-Signature:[^\n]*(?:\n[ \t][^\n]*)*', headers, re.M | re.I)
    assert signature and re.search(rf'\bd={re.escape(r.domain)};', signature.group(0)), 'no DKIM-Signature of the domain'
    return f'DKIM-Signature d={r.domain}'


CHECKS = (
    ('BEC VIP name (8c)', check_bec_vip),
    ('attachment: program by content', check_attachment_executable),
    ('graymail mark (9d)', check_graymail),
    ('own block: SHA-256 (M5)', check_own_hash),
    ('job applications (8j)', check_applications),
    ('job applications, all domains', check_applications_all),
    ('warning banner', check_banner),
    ('link check', check_links),
    ('tracking protection (M1)', check_tracking),
    ('DLP IBAN outgoing', check_dlp),
    ('header privacy outgoing (M2)', check_header_privacy),
    ('DKIM outgoing', check_dkim),
)


def main():
    domain, run = sys.argv[1].lower(), sys.argv[2]
    only = set(sys.argv[3].split(',')) if len(sys.argv) > 3 and sys.argv[3] else None
    r = Run(domain, run)
    results = {}
    try:
        for name, check in CHECKS:
            if only and check.__name__[len('check_'):] not in only:
                continue
            undo = []
            try:
                results[name] = 'ok (' + check(r, undo) + ')'
            except Skip as why:
                results[name] = f'SKIPPED ({why})'
            except (AssertionError, RuntimeError, OSError, ValueError, KeyError) as err:
                results[name] = f'FAILED ({str(err)[:220]})'
            finally:
                for step in reversed(undo):
                    try:
                        step()
                    except (RuntimeError, OSError) as err:
                        results[name + ': put back'] = f'FAILED ({str(err)[:160]})'
    finally:
        results['queue clean'] = 'ok' if r.cleanup() else 'FAILED (mails of the run left in the queue)'
    for name, result in results.items():
        print(f'features {name}: {result}')
    return 0 if all(not result.startswith('FAILED') for result in results.values()) else 1


if __name__ == '__main__':
    sys.exit(main())
