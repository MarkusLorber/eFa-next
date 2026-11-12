#!/usr/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Markus Lorber and eFa-next contributors
# Author: Markus Lorber, Lukasz Galusinski
"""MIG-LE on the installed host (ci.sh --install): a certbot lineage of eFa 5 (RSA, apache in the renewal file), issued by a
local test CA (root and intermediate, trusted only for this run), goes to nginx and Postfix through efactl letsencrypt-takeover.
Checked: nginx serves it, Postfix uses it, the key file is byte for byte the same, the renewal keeps the key and RSA and runs
through the webroot, certbot reads the lineage. Everything is put back afterwards. A host with its own lineage is left alone.
The real case (a certificate of Let's Encrypt) is checked on the first real host."""
import datetime
import os
import shutil
import subprocess
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

LE = '/etc/letsencrypt'
NGINX_CONF = '/etc/nginx/conf.d/efa.conf'
ACME_FILE = '/etc/eFa/acme.json'
CRON = '/etc/cron.d/certbotrenew'
ANCHOR = '/etc/pki/ca-trust/source/anchors/efa-ci-le-test.pem'


def run(*cmd, check=True):
    done = subprocess.run(cmd, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise SystemExit(f'{" ".join(cmd)}: {(done.stdout + done.stderr)[-400:]}')
    return done.stdout


def name_of(text):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, text)])


def issue(subject, issuer, issuer_key, key, ca, names=()):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name_of(subject)).issuer_name(name_of(issuer)).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(hours=1))
               .not_valid_after(now + datetime.timedelta(days=60)).add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        builder = builder.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
    return builder.sign(issuer_key, hashes.SHA256())


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def lineage(name):
    """A lineage as certbot lays it out: archive/<name>/*1.pem, live/<name>/* as links, renewal/<name>.conf of eFa 5."""
    root_key, mid_key, key = (rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3))
    root = issue('eFa-next CI test root', 'eFa-next CI test root', root_key, root_key, True)
    mid = issue('eFa-next CI test R1', 'eFa-next CI test root', root_key, mid_key, True)
    leaf = issue(name, 'eFa-next CI test R1', mid_key, key, False, [name])
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    archive, live = f'{LE}/archive/{name}', f'{LE}/live/{name}'
    for folder in (archive, live, LE + '/renewal'):
        os.makedirs(folder, exist_ok=True)
    files = {'cert': pem(leaf), 'chain': pem(mid), 'fullchain': pem(leaf) + pem(mid), 'privkey': key_pem}
    for item, data in files.items():
        with open(f'{archive}/{item}1.pem', 'wb') as f:
            f.write(data)
        os.symlink(f'../../archive/{name}/{item}1.pem', f'{live}/{item}.pem')
    os.chmod(f'{archive}/privkey1.pem', 0o600)
    with open(f'{LE}/renewal/{name}.conf', 'w') as f:
        f.write(f'version = 1.22.0\narchive_dir = {archive}\ncert = {live}/cert.pem\nprivkey = {live}/privkey.pem\n'
                f'chain = {live}/chain.pem\nfullchain = {live}/fullchain.pem\n\n[renewalparams]\naccount = 0123456789abcdef\n'
                'authenticator = apache\ninstaller = apache\nserver = https://acme-v02.api.letsencrypt.org/directory\n'
                'key_type = rsa\nrsa_key_size = 2048\npre_hook = systemctl stop httpd\n')
    return pem(root), leaf, key_pem


def served(name):
    """The certificate nginx hands out for this name."""
    out = subprocess.run(['openssl', 's_client', '-connect', '127.0.0.1:443', '-servername', name], input='', capture_output=True,
                         text=True, timeout=30).stdout
    start = out.find('-----BEGIN CERTIFICATE-----')
    end = out.find('-----END CERTIFICATE-----', start)
    return x509.load_pem_x509_certificate((out[start:end] + '-----END CERTIFICATE-----\n').encode()) if start >= 0 else None


def main():
    name = run('postconf', '-h', 'myhostname').strip()
    if os.path.exists(ACME_FILE) or os.path.exists(f'{LE}/live/{name}') or os.path.exists(f'{LE}/renewal/{name}.conf'):
        print(f'le-takeover-live: skipped, this host has its own lineage for {name}')
        return 0
    saved = {'conf': open(NGINX_CONF).read(), 'cron': open(CRON).read() if os.path.exists(CRON) else None,
             'postfix': {k: run('postconf', '-h', k).strip() for k in ('smtpd_tls_cert_file', 'smtpd_tls_key_file')}, 'le': os.path.isdir(LE)}
    try:
        root, leaf, key_pem = lineage(name)
        with open(ANCHOR, 'wb') as f:
            f.write(root)
        run('update-ca-trust', 'extract')
        out = run('/usr/sbin/efactl', 'letsencrypt-takeover')
        print(out.strip())
        live = f'{LE}/live/{name}'
        conf = open(NGINX_CONF).read()
        assert f'ssl_certificate {live}/fullchain.pem;' in conf and f'ssl_certificate_key {live}/privkey.pem;' in conf, conf
        assert run('postconf', '-h', 'smtpd_tls_cert_file').strip() == f'{live}/fullchain.pem'
        assert run('postconf', '-h', 'smtpd_tls_key_file').strip() == f'{live}/privkey.pem'
        with open(f'{live}/privkey.pem', 'rb') as f:
            assert f.read() == key_pem, 'the key is the same'
        got = served(name)
        assert got is not None and got.fingerprint(hashes.SHA256()) == leaf.fingerprint(hashes.SHA256()), 'nginx serves the lineage'
        renewal = open(f'{LE}/renewal/{name}.conf').read()
        for wanted in ('reuse_key = True', 'key_type = rsa', 'rsa_key_size = 2048', 'authenticator = webroot', '[[webroot_map]]'):
            assert wanted in renewal, (wanted, renewal)
        assert 'apache' not in renewal and 'pre_hook' not in renewal, renewal
        assert 'certbot renew' in open(CRON).read()
        if shutil.which('certbot'):
            listed = run('certbot', 'certificates', '--cert-name', name)
            assert name in listed and 'RSA' in listed, listed
        print('le-takeover-live: ok')
        return 0
    finally:
        with open(NGINX_CONF, 'w') as f:
            f.write(saved['conf'])
        if saved['cron'] is None:
            if os.path.exists(CRON):
                os.remove(CRON)
        else:
            with open(CRON, 'w') as f:
                f.write(saved['cron'])
        for key, value in saved['postfix'].items():
            run('postconf', '-e', f'{key} = {value}', check=False)
        for path in (ACME_FILE, ANCHOR):
            if os.path.exists(path):
                os.remove(path)
        run('update-ca-trust', 'extract', check=False)
        for folder in (f'{LE}/archive/{name}', f'{LE}/live/{name}'):
            shutil.rmtree(folder, ignore_errors=True)
        for path in (f'{LE}/renewal/{name}.conf', f'{LE}/renewal/{name}.conf.efa-takeover.bak'):
            if os.path.exists(path):
                os.remove(path)
        if not saved['le']:
            shutil.rmtree(LE, ignore_errors=True)
        run('systemctl', 'reload', 'nginx', check=False)
        run('systemctl', 'reload', 'postfix', check=False)


if __name__ == '__main__':
    sys.exit(main())
