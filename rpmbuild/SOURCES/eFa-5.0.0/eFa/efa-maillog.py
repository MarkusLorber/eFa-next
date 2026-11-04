#!/usr/bin/python3
"""Stores rspamd scan results in MariaDB. rspamd posts one JSON document per message to 127.0.0.1:8906.

shortcut: any local process can post log entries, add a shared secret if untrusted local users ever exist.
"""
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pymysql

PASSWORD_FILE = '/etc/efa-web/maillog.pw'
MAX_BODY = 1024 * 1024


def connect():
    with open(PASSWORD_FILE) as f:
        password = f.read().strip()
    return pymysql.connect(unix_socket='/var/lib/mysql/mysql.sock', user='efa_log', password=password,
                           database='efa', charset='utf8mb4', autocommit=True)


def text(value, limit):
    if isinstance(value, list):
        value = ', '.join(str(v) for v in value)
    return str(value if value is not None else '')[:limit]


def row(doc):
    return (float(doc.get('unix_time') or 0), text(doc.get('qid'), 64), text(doc.get('message_id'), 255),
            text(doc.get('from'), 255), text(doc.get('rcpt'), 1000), text(doc.get('ip'), 64),
            text(doc.get('action'), 32), float(doc.get('score') or 0), text(doc.get('subject'), 500))


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        if not 0 < length <= MAX_BODY:
            self.send_error(413)
            return
        try:
            values = row(json.loads(self.rfile.read(length)))
            db = connect()
            try:
                with db.cursor() as cur:
                    cur.execute('INSERT INTO maillog (ts, qid, message_id, sender, rcpt, ip, action, score, subject) '
                                'VALUES (FROM_UNIXTIME(%s), %s, %s, %s, %s, %s, %s, %s, %s)', values)
            finally:
                db.close()
        except (ValueError, pymysql.MySQLError, OSError) as err:
            # Logging must never affect mail flow, rspamd only records the failure.
            logging.error('maillog insert failed: %s', err)
            self.send_error(500)
            return
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', 8906), Handler).serve_forever()
