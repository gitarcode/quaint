#!/usr/bin/env python3
"""Run isolated Postgres TLS fixtures. Requires Docker and OpenSSL 3."""
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent
OPENSSL = os.environ.get('OPENSSL_BIN', 'openssl')

def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

with tempfile.TemporaryDirectory(prefix='quaint-rustls-') as directory:
    certs = Path(directory)
    certs.chmod(0o755)
    def ssl(*args):
        run(OPENSSL, *args, cwd=certs, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    ssl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.crt', '-days', '2', '-subj', '/CN=Quaint fixture CA')
    (certs/'index').touch()
    (certs/'serial').write_text('1000\n')
    (certs/'ca.conf').write_text('[ca]\ndefault_ca=fixture\n[fixture]\ndatabase=index\nserial=serial\nnew_certs_dir=.\ndefault_md=sha256\npolicy=policy\n[policy]\ncommonName=supplied\n')
    for name, cn, usage, days in [('server', 'localhost', 'serverAuth', '2'), ('expired', 'localhost', 'serverAuth', '-1'), ('client', 'certuser', 'clientAuth', '2')]:
        ssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', name+'.key', '-out', name+'.csr', '-subj', '/CN='+cn)
        (certs/(name+'.ext')).write_text('basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage='+usage+'\n'+('subjectAltName=DNS:localhost\n' if usage=='serverAuth' else ''))
        if name == 'expired':
            ssl('ca', '-batch', '-config', 'ca.conf', '-keyfile', 'ca.key', '-cert', 'ca.crt', '-in', name+'.csr', '-out', name+'.crt', '-startdate', '20000101000000Z', '-enddate', '20000102000000Z', '-extfile', name+'.ext')
        else:
            ssl('x509', '-req', '-in', name+'.csr', '-CA', 'ca.crt', '-CAkey', 'ca.key', '-CAcreateserial', '-out', name+'.crt', '-days', days, '-extfile', name+'.ext')
    for name, extra in [('client.p12', []), ('client-legacy.p12', ['-legacy'])]:
        ssl('pkcs12', '-export', '-inkey', 'client.key', '-in', 'client.crt', '-certfile', 'ca.crt', '-out', name, '-passout', 'pass:fixture-password', *extra)
    (certs/'not-a-cert.pem').write_text('not a certificate\n')
    (certs/'init.sh').write_text('''#!/bin/sh
set -eu
psql -v ON_ERROR_STOP=1 --username postgres --dbname postgres -c 'CREATE USER certuser'
cat > "$PGDATA/pg_hba.conf" <<'HBA'
local all all trust
hostssl all certuser all cert
host all all all scram-sha-256
HBA
''')
    for path in certs.iterdir():
        path.chmod(0o644)
    containers = []
    env = os.environ.copy()
    env.pop('SSL_CERT_FILE', None)
    env.pop('SSL_CERT_DIR', None)
    env['QUAINT_TEST_CERTS'] = directory
    try:
        for kind in ['TLS', 'PLAIN', 'EXPIRED']:
            args = ['docker', 'run', '-d', '--rm', '-p', '127.0.0.1::5432', '-e', 'POSTGRES_PASSWORD=fixture-password', '-v', directory+':/certs:ro', '-v', str(certs/'init.sh')+':/docker-entrypoint-initdb.d/quaint.sh:ro', 'postgres:17', 'bash', '-c', 'mkdir /tls && cp /certs/*.crt /certs/*.key /tls/ && chown postgres:postgres /tls/* && chmod 600 /tls/*.key && exec docker-entrypoint.sh "$@"', '--', 'postgres', '-c', 'ssl='+('off' if kind=='PLAIN' else 'on')]
            if kind != 'PLAIN':
                name = 'expired' if kind=='EXPIRED' else 'server'
                args += ['-c', 'ssl_cert_file=/tls/'+name+'.crt', '-c', 'ssl_key_file=/tls/'+name+'.key', '-c', 'ssl_ca_file=/tls/ca.crt']
            cid = run(*args, capture_output=True, text=True).stdout.strip()
            containers.append(cid)
            port = run('docker', 'port', cid, '5432', capture_output=True, text=True).stdout.strip().rsplit(':', 1)[-1]
            for attempt in range(60):
                # TCP readiness excludes the temporary initdb server's Unix socket.
                ready = subprocess.run(['docker', 'exec', cid, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if ready.returncode == 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError('Postgres fixture did not start: '+kind)
            env['QUAINT_TEST_'+kind+'_URL'] = f'postgresql://postgres:fixture-password@localhost:{port}/postgres'
        run('cargo', 'test', '--locked', '--manifest-path', str(ROOT/'Cargo.toml'), env=env)
        env['SSL_CERT_FILE'] = str(certs/'ca.crt')
        run('cargo', 'test', '--locked', '--manifest-path', str(ROOT/'Cargo.toml'), 'system_roots_are_used', '--', '--ignored', env=env)
    finally:
        for cid in containers:
            subprocess.run(['docker', 'rm', '-f', cid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
