#!/usr/bin/python3 -I
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""Load and performance test of eFa-next (Q11): generated mail (text, HTML with links, attachments, 2 to 200 KB, fixed seed)
through the filter, with mails per minute, latency (median, 95th percentile) and the memory of the services.

    load_test.py [--mode rspamd|smtp] [--mails N] [--parallel N] [--markdown]
    rspamd: each mail to rspamd for a check only (checkv2); changes nothing, used in CI.
    smtp:   each mail through Postfix with all milters to --to, whose domain must route to the sink of this script:
            efactl transport-set --domain load-test.example --action add --destination 127.0.0.1:2526
            The sink takes the mails on --sink-port and measures the time from sending to arrival.
            Careful: these mails pass the normal mail flow, so rspamd learns them by autolearn (Bayes). Generated words then
            make real mail look like spam. Only on a test system whose Bayes data may be reset after, with --allow-learning.
"""
import argparse
import email.message
import json
import os
import random
import smtplib
import statistics
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

WORDS = ('angebot rechnung termin projekt bericht freigabe kunde lieferung meeting update offer invoice schedule report '
         'contract delivery payment account review planning budget quarter result team support ticket order').split()


def generate(rng, index, to):
    """One mail; about one in four with HTML and links, one in five with an attachment."""
    message = email.message.EmailMessage()
    message['From'], message['To'] = f'load{index % 50}@load-sender.example', to
    message['Subject'] = ' '.join(rng.choice(WORDS) for _ in range(rng.randint(3, 8)))
    message['Message-ID'] = f'<load-{index}-{rng.getrandbits(32):08x}@load-sender.example>'
    message['X-Load-Sent'] = '0'
    text = '\n\n'.join(' '.join(rng.choice(WORDS) for _ in range(rng.randint(20, 120))) for _ in range(rng.randint(1, 12)))
    message.set_content(text)
    if rng.random() < 0.25:
        links = ''.join(f'<p><a href="https://www.example-{rng.randint(1, 500)}.com/{rng.choice(WORDS)}">{rng.choice(WORDS)}</a></p>'
                        for _ in range(rng.randint(1, 6)))
        message.add_alternative(f'<html><body><p>{text[:2000]}</p>{links}</body></html>', subtype='html')
    if rng.random() < 0.2:
        size = rng.choice((2, 20, 60, 150)) * 1024
        message.add_attachment(rng.randbytes(size), maintype='application', subtype='pdf', filename=f'{rng.choice(WORDS)}.pdf')
    return message


def percentile(values, share):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(share * (len(ordered) - 1))))] if ordered else None


def memory():
    """Resident memory in MB of the services that do the work."""
    out = {}
    for name in ('rspamd', 'clamd', 'master', 'smtpd', 'cleanup', 'python3', 'redis-server', 'mariadbd'):
        done = subprocess.run(['ps', '-C', name, '-o', 'rss='], capture_output=True, text=True)
        total = sum(int(item) for item in done.stdout.split() if item.isdigit())
        if total:
            out[name] = round(total / 1024)
    return out


def host():
    pages = os.sysconf('SC_PHYS_PAGES') if hasattr(os, 'sysconf') else 0
    size = os.sysconf('SC_PAGE_SIZE') if hasattr(os, 'sysconf') else 0
    return {'cpus': os.cpu_count(), 'ram_mb': round(pages * size / 1048576) if pages and size else None}


class Sink:
    """A small SMTP receiver: answers like a mail server and notes the arrival time of each load mail."""

    def __init__(self, port):
        import socketserver
        self.arrived, self.lock = [], threading.Lock()
        sink = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.wfile.write(b'220 sink ESMTP\r\n')
                data, in_data = [], False
                for line in self.rfile:
                    if in_data:
                        if line in (b'.\r\n', b'.\n'):
                            in_data = False
                            raw = b''.join(data)
                            data = []
                            for header in raw.split(b'\r\n\r\n', 1)[0].split(b'\r\n'):
                                if header.lower().startswith(b'x-load-sent:'):
                                    with sink.lock:
                                        sink.arrived.append(time.time() - float(header.split(b':', 1)[1]))
                            self.wfile.write(b'250 2.0.0 ok\r\n')
                        else:
                            data.append(line)
                        continue
                    command = line[:4].upper()
                    if command == b'DATA':
                        in_data = True
                        self.wfile.write(b'354 go on\r\n')
                    elif command == b'QUIT':
                        self.wfile.write(b'221 bye\r\n')
                        return
                    elif command in (b'EHLO', b'HELO'):
                        self.wfile.write(b'250 sink\r\n')
                    else:
                        self.wfile.write(b'250 ok\r\n')

        class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
            allow_reuse_address, daemon_threads = True, True
        self.server = Server(('127.0.0.1', port), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def times(self):
        with self.lock:
            return list(self.arrived)


def run(args):
    rng = random.Random(args.seed)
    messages = [generate(rng, index, args.to) for index in range(args.mails)]
    latencies, failures = [], []
    sink = Sink(args.sink_port) if args.mode == 'smtp' else None

    def one(message):
        start = time.time()
        try:
            if args.mode == 'rspamd':
                request = urllib.request.Request(args.url.rstrip('/') + '/checkv2', data=message.as_bytes(), method='POST')
                with urllib.request.urlopen(request, timeout=120) as answer:
                    json.load(answer)
            else:
                message.replace_header('X-Load-Sent', f'{start:.6f}')
                with smtplib.SMTP('127.0.0.1', 25, timeout=120) as server:
                    server.send_message(message, from_addr=message['From'], to_addrs=[args.to])
            latencies.append(time.time() - start)
        except (OSError, ValueError, smtplib.SMTPException) as err:
            failures.append(str(err)[:120])

    before = memory()
    begin = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.parallel) as pool:
        list(pool.map(one, messages))
    if sink:
        deadline = time.monotonic() + args.wait
        while len(sink.times()) < len(latencies) and time.monotonic() < deadline:
            time.sleep(0.5)
    seconds = time.monotonic() - begin
    done = sink.times() if sink else latencies
    return {'mode': args.mode, 'mails': args.mails, 'parallel': args.parallel, 'host': host(),
            'delivered' if sink else 'checked': len(done), 'failed': len(failures), 'failures': failures[:5],
            'mails_per_minute': round(60 * len(done) / seconds) if seconds else None,
            'latency_s': {'median': round(statistics.median(done), 3) if done else None, 'p95': round(percentile(done, 0.95), 3) if done else None},
            'memory_mb_before': before, 'memory_mb_after': memory(), 'seconds': round(seconds, 1)}


def markdown(result):
    return '\n'.join([
        f"# Load test ({result['mode']})", '',
        f"Host: {result['host']['cpus']} CPUs, {result['host']['ram_mb']} MB RAM. {result['mails']} mails, {result['parallel']} at a time.", '',
        '| Mails per minute | Latency median | Latency 95 % | Failed |', '| --- | --- | --- | --- |',
        f"| {result['mails_per_minute']} | {result['latency_s']['median']} s | {result['latency_s']['p95']} s | {result['failed']} |", '',
        f"Memory in MB after the run: {result['memory_mb_after']}", ''])


def self_test():
    rng = random.Random(1)
    sample = [generate(rng, index, 'x@load-test.example') for index in range(200)]
    sizes = [len(message.as_bytes()) for message in sample]
    assert min(sizes) > 200 and max(sizes) < 300 * 1024 and any(message.get_body(('html',)) for message in sample)
    assert any(list(message.iter_attachments()) for message in sample)
    assert [m['Subject'] for m in (generate(random.Random(1), 0, 'x@y'),)] == [sample[0]['Subject']], 'same seed, same mail'
    assert percentile([1, 2, 3, 4, 100], 0.95) == 100 and percentile([], 0.5) is None
    print('self-test ok')


def main():
    if '--self-test' in sys.argv:
        self_test()
        return 0
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--mode', choices=('rspamd', 'smtp'), default='rspamd')
    ap.add_argument('--mails', type=int, default=200)
    ap.add_argument('--parallel', type=int, default=8)
    ap.add_argument('--url', default='http://127.0.0.1:11333')
    ap.add_argument('--to', default='load@load-test.example')
    ap.add_argument('--sink-port', type=int, default=2526)
    ap.add_argument('--wait', type=int, default=300, help='smtp: seconds to wait for the last mails at the sink')
    ap.add_argument('--seed', type=int, default=6004)
    ap.add_argument('--markdown', action='store_true')
    ap.add_argument('--max-failed', type=float, default=1.0, help='percent of failed mails that still counts as passed')
    ap.add_argument('--allow-learning', action='store_true', help='smtp: accept that rspamd learns the generated mails (Bayes)')
    args = ap.parse_args()
    if args.mode == 'smtp' and not args.allow_learning:
        print('smtp mode trains Bayes with generated mail by autolearn; on a test system only, then with --allow-learning', file=sys.stderr)
        return 2
    result = run(args)
    print(markdown(result) if args.markdown else json.dumps(result, indent=1))
    return 1 if result['failed'] > args.mails * args.max_failed / 100 else 0


if __name__ == '__main__':
    sys.exit(main())
