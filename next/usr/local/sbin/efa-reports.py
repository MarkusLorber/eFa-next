#!/usr/bin/python3
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Reads DMARC aggregate reports (RFC 7489: XML, gzip or zip) and TLS reports (RFC 8460: JSON, gzip) from one mail on stdin,
as the Postfix pipe of the report address, and stores them in the eFa-next database. Standard library and PyMySQL only.
Exit 0 when done or when the mail holds no report, 75 so Postfix tries again when the database does not answer."""
import email
import email.errors
import email.policy
import gzip
import io
import json
import os
import sys
import syslog
import zipfile
import zlib
import xml.etree.ElementTree as ElementTree
from datetime import datetime, timezone

# The programs live under /usr/local/sbin, the shared library under /usr/lib/eFa/python; next to this file in a source tree.
for _folder in ('/usr/lib/eFa/python', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'lib', 'eFa', 'python')):
    if os.path.isdir(_folder) and _folder not in sys.path:
        sys.path.insert(0, _folder)
import efa_zip  # noqa: E402

MAX_MAIL = 10 * 1024 * 1024
# A small compressed file can unpack to gigabytes: nothing unpacks to more than this.
MAX_UNPACKED = 20 * 1024 * 1024
MAX_ROWS = 50000
MAILLOG_PW = '/etc/efa-web/maillog.pw'
EX_TEMPFAIL = 75


def unpack(name, data, depth=0):
    """The report files of one attachment: (kind, bytes), kind 'xml' or 'json'. depth bounds nested archives (a zip bomb)."""
    if depth > 2:
        raise ValueError('report nested too deeply')
    lower = name.lower()
    if data[:2] == b'\x1f\x8b':
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as packed:
            data = packed.read(MAX_UNPACKED + 1)
        if len(data) > MAX_UNPACKED:
            raise ValueError('unpacks to more than allowed')
        lower = lower.removesuffix('.gz')
    elif data[:2] == b'PK':
        found = []
        for member, content in efa_zip.safe_unzip(data, max_files=5, max_total=MAX_UNPACKED).items():
            found += unpack(member, content, depth + 1)
        return found
    text = data.lstrip()
    if lower.endswith('.json') or text[:1] == b'{':
        return [('json', data)]
    if lower.endswith('.xml') or text[:5] == b'<?xml' or text[:9] == b'<feedback':
        return [('xml', data)]
    return []


def _text(node, path, default=''):
    found = node.find(path)
    return (found.text or '').strip() if found is not None and found.text else default


def parse_dmarc(data):
    """Rows of a DMARC aggregate report. Entities are refused: a report never needs them."""
    # Decode first, so a DOCTYPE in UTF-16 (where a byte search for '<!DOCTYPE' would miss it) is still caught.
    if data[:2] in (b'\xff\xfe', b'\xfe\xff') or data[:1] == b'\x00' or data[1:2] == b'\x00':
        text = data.decode('utf-16', 'replace')
    elif data[:3] == b'\xef\xbb\xbf':
        text = data.decode('utf-8-sig', 'replace')
    else:
        text = data.decode('utf-8', 'replace')
    if '<!ENTITY' in text or '<!DOCTYPE' in text:
        raise ValueError('a report with DOCTYPE or entities')
    root = ElementTree.fromstring(text)
    if root.tag != 'feedback':
        raise ValueError('no DMARC feedback')
    org, report_id = _text(root, 'report_metadata/org_name')[:255], _text(root, 'report_metadata/report_id')[:255]
    begin, end = int(_text(root, 'report_metadata/date_range/begin', '0')), int(_text(root, 'report_metadata/date_range/end', '0'))
    domain = _text(root, 'policy_published/domain').lower()[:253]
    rows = []
    for record in root.findall('record')[:MAX_ROWS]:
        rows.append({'report_id': report_id, 'org': org, 'domain': domain, 'begin': begin, 'end': end,
                     'source_ip': _text(record, 'row/source_ip')[:64], 'n': int(_text(record, 'row/count', '0')),
                     'disposition': _text(record, 'row/policy_evaluated/disposition', 'none')[:16],
                     'dkim': _text(record, 'row/policy_evaluated/dkim', 'none')[:16], 'spf': _text(record, 'row/policy_evaluated/spf', 'none')[:16],
                     'header_from': _text(record, 'identifiers/header_from').lower()[:253]})
    if not report_id or not domain:
        raise ValueError('a report without ID or domain')
    return rows


def _stamp(text):
    return int(datetime.fromisoformat(text.replace('Z', '+00:00')).astimezone(timezone.utc).timestamp())


def parse_tlsrpt(data):
    """Rows of a TLS report, one per policy."""
    report = json.loads(data)
    org, report_id = str(report.get('organization-name', ''))[:255], str(report.get('report-id', ''))[:255]
    begin, end = _stamp(report['date-range']['start-datetime']), _stamp(report['date-range']['end-datetime'])
    rows = []
    for item in report.get('policies', [])[:MAX_ROWS]:
        policy, summary = item.get('policy', {}), item.get('summary', {})
        failures = [{'type': str(detail.get('result-type', ''))[:64], 'mx': str(detail.get('receiving-mx-hostname', ''))[:253],
                     'count': int(detail.get('failed-session-count', 0))} for detail in item.get('failure-details', [])[:100]]
        rows.append({'report_id': report_id, 'org': org, 'domain': str(policy.get('policy-domain', '')).lower()[:253], 'begin': begin, 'end': end,
                     'policy': str(policy.get('policy-type', ''))[:16], 'success': int(summary.get('total-successful-session-count', 0)),
                     'failure': int(summary.get('total-failure-session-count', 0)), 'failures': json.dumps(failures)})
    if not report_id:
        raise ValueError('a report without ID')
    return rows


# Whatever a broken report raises: it is only not read. Found by fuzzing (scripts/fuzz.py).
READ_ERRORS = (ValueError, KeyError, TypeError, OSError, LookupError, AttributeError, OverflowError, zipfile.BadZipFile,
               ElementTree.ParseError, EOFError, RecursionError, zlib.error,
               NotImplementedError, RuntimeError)  # an unknown zip compression, an encrypted zip


def reports_of(raw):
    """DMARC and TLS rows of one mail, and the names of the parts that could not be read."""
    dmarc, tls, bad = [], [], []
    try:
        parts = list(email.message_from_bytes(raw, policy=email.policy.default).walk())
    except READ_ERRORS + (IndexError, email.errors.MessageError) as err:  # Python 3.9 cannot parse every structure
        return dmarc, tls, [f'the mail: {err}'[:200]]
    for part in parts:
        if part.is_multipart():
            continue
        name = part.get_filename() or ''
        data = part.get_payload(decode=True) or b''
        if not data or not (name or part.get_content_type() in ('application/gzip', 'application/zip', 'application/tlsrpt+gzip',
                                                                  'application/tlsrpt+json', 'text/xml', 'application/xml')):
            continue
        try:
            for kind, content in unpack(name or 'report', data):
                if kind == 'xml':
                    dmarc += parse_dmarc(content)
                else:
                    tls += parse_tlsrpt(content)
        except READ_ERRORS as err:
            bad.append(f'{name or part.get_content_type()}: {err}'[:200])
    return dmarc, tls, bad


def store(dmarc, tls):
    import pymysql
    with open(MAILLOG_PW) as f:
        password = f.read().strip()
    db = pymysql.connect(unix_socket='/var/lib/mysql/mysql.sock', user='efa_log', password=password, database='efa', autocommit=True)
    try:
        with db.cursor() as cur:
            if dmarc:
                cur.executemany('INSERT IGNORE INTO dmarc_rua (report_id, org, domain, begin_ts, end_ts, source_ip, n, disposition, dkim, spf, header_from) '
                                'VALUES (%s, %s, %s, FROM_UNIXTIME(%s), FROM_UNIXTIME(%s), %s, %s, %s, %s, %s, %s)',
                                [(r['report_id'], r['org'], r['domain'], r['begin'], r['end'], r['source_ip'], r['n'], r['disposition'], r['dkim'],
                                  r['spf'], r['header_from']) for r in dmarc])
            if tls:
                cur.executemany('INSERT IGNORE INTO tls_rpt (report_id, org, domain, begin_ts, end_ts, policy, success, failure, failures) '
                                'VALUES (%s, %s, %s, FROM_UNIXTIME(%s), FROM_UNIXTIME(%s), %s, %s, %s, %s)',
                                [(r['report_id'], r['org'], r['domain'], r['begin'], r['end'], r['policy'], r['success'], r['failure'], r['failures'])
                                 for r in tls])
    finally:
        db.close()


def main():
    syslog.openlog('efa-reports', 0, syslog.LOG_MAIL)
    raw = sys.stdin.buffer.read(MAX_MAIL + 1)
    if len(raw) > MAX_MAIL:
        syslog.syslog(syslog.LOG_WARNING, 'a report mail larger than 10 MB was not read')
        return 0
    dmarc, tls, bad = reports_of(raw)
    for item in bad:
        syslog.syslog(syslog.LOG_WARNING, f'not read: {item}')
    if not dmarc and not tls:
        return 0
    try:
        store(dmarc, tls)
    except Exception as err:  # PyMySQL errors and a missing password file: Postfix keeps the mail and tries again
        syslog.syslog(syslog.LOG_ERR, f'database: {err}')
        return EX_TEMPFAIL
    syslog.syslog(syslog.LOG_INFO, f'stored {len(dmarc)} DMARC rows and {len(tls)} TLS rows')
    return 0


DMARC_SAMPLE = b'''<?xml version="1.0" encoding="UTF-8" ?>
<feedback><report_metadata><org_name>google.com</org_name><report_id>123</report_id>
<date_range><begin>1730764800</begin><end>1730851199</end></date_range></report_metadata>
<policy_published><domain>own.example</domain><p>none</p></policy_published>
<record><row><source_ip>192.0.2.10</source_ip><count>5</count><policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf>
</policy_evaluated></row><identifiers><header_from>own.example</header_from></identifiers></record>
<record><row><source_ip>198.51.100.7</source_ip><count>12</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf>
</policy_evaluated></row><identifiers><header_from>own.example</header_from></identifiers></record></feedback>'''
TLS_SAMPLE = json.dumps({'organization-name': 'Google Inc.', 'report-id': '2026-11-05T00:00:00Z_own.example',
                         'date-range': {'start-datetime': '2026-11-05T00:00:00Z', 'end-datetime': '2026-11-05T23:59:59Z'},
                         'policies': [{'policy': {'policy-type': 'sts', 'policy-domain': 'own.example'},
                                       'summary': {'total-successful-session-count': 40, 'total-failure-session-count': 2},
                                       'failure-details': [{'result-type': 'certificate-expired', 'receiving-mx-hostname': 'mx.own.example',
                                                            'failed-session-count': 2}]}]}).encode()


def self_test():
    rows = parse_dmarc(DMARC_SAMPLE)
    assert len(rows) == 2 and rows[1] == {'report_id': '123', 'org': 'google.com', 'domain': 'own.example', 'begin': 1730764800, 'end': 1730851199,
                                          'source_ip': '198.51.100.7', 'n': 12, 'disposition': 'none', 'dkim': 'fail', 'spf': 'fail',
                                          'header_from': 'own.example'}, rows
    tls = parse_tlsrpt(TLS_SAMPLE)
    assert tls[0]['policy'] == 'sts' and tls[0]['failure'] == 2 and json.loads(tls[0]['failures'])[0]['type'] == 'certificate-expired'
    # A DOCTYPE is refused even when the report is UTF-16: the check reads the decoded text, not the raw bytes.
    for bad_doc in (b'<!DOCTYPE x [<!ENTITY a "a">]><feedback/>', '<!DOCTYPE x><feedback/>'.encode('utf-16')):
        try:
            parse_dmarc(bad_doc)
            raise AssertionError('a DOCTYPE report was parsed')
        except ValueError:
            pass
    message = email.message.EmailMessage()
    message['From'], message['To'], message['Subject'] = 'noreply-dmarc-support@google.com', 'reports@own.example', 'Report domain: own.example'
    message.set_content('Report attached.')
    message.add_attachment(gzip.compress(DMARC_SAMPLE), maintype='application', subtype='gzip', filename='google.com!own.example!1!2.xml.gz')
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('report.xml', DMARC_SAMPLE)
    message.add_attachment(archive.getvalue(), maintype='application', subtype='zip', filename='report.zip')
    message.add_attachment(gzip.compress(TLS_SAMPLE), maintype='application', subtype='tlsrpt+gzip', filename='google.com!own.example!1!2.json.gz')
    message.add_attachment(b'<!DOCTYPE x [<!ENTITY a "aaaa">]><feedback/>', maintype='text', subtype='xml', filename='bomb.xml')
    message.add_attachment(gzip.compress(b'0' * (MAX_UNPACKED + 10)), maintype='application', subtype='gzip', filename='big.xml.gz')
    dmarc, tls_rows, bad = reports_of(message.as_bytes())
    assert len(dmarc) == 4 and len(tls_rows) == 1 and len(bad) == 2, (len(dmarc), len(tls_rows), bad)
    # Q2: mutated reports never make it fail, they only end up as unread.
    import random
    generator = random.Random(7)
    for sample in (DMARC_SAMPLE, TLS_SAMPLE):
        for _ in range(300):
            data = bytearray(sample)
            for _ in range(generator.randint(1, 8)):
                data[generator.randrange(len(data))] = generator.randrange(256)
            fuzz = email.message.EmailMessage()
            fuzz.set_content('x')
            fuzz.add_attachment(bytes(data), maintype='application', subtype='octet-stream', filename='r.xml' if sample is DMARC_SAMPLE else 'r.json')
            reports_of(fuzz.as_bytes())
    print('self-test ok')


if __name__ == '__main__':
    if '--self-test' in sys.argv:
        self_test()
    else:
        sys.exit(main())
