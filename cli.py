"""Command line interface:  python -m credentials <command> --help"""
import argparse
import secrets
import sys
from pathlib import Path

from .config import ConfigError, load_admin_token
from .service import MAX_PDF_BYTES, TYPES, CredentialError, IntegrityError, Service


def build_parser():
    p = argparse.ArgumentParser(prog='python -m credentials',
                                description='Issue and verify signed credentials.')
    sub = p.add_subparsers(dest='command', required=True)

    g = sub.add_parser('genkey', help='print a new signing key and admin API token')
    g.add_argument('--id', default='k1', help='key id (1-8 letters or digits), default k1')

    i = sub.add_parser('issue', help='issue a credential and its PDF')
    i.add_argument('--name', required=True, help='holder name')
    i.add_argument('--type', required=True, choices=list(TYPES), dest='ctype')
    i.add_argument('--org', default='')
    i.add_argument('--purpose', default='', help='required for noc and approval')
    i.add_argument('--days', type=int, default=365, help='validity in days (default 365)')
    i.add_argument('--base-url', default=None, help='address encoded in the QR code')

    v = sub.add_parser('verify', help='check a token; exit code 0 only if valid')
    v.add_argument('token')

    r = sub.add_parser('revoke', help='revoke a credential')
    r.add_argument('serial')
    r.add_argument('--reason', default='')

    sub.add_parser('list', help='list issued credentials')
    sub.add_parser('audit', help='re-hash every stored PDF; exit code 1 if any differs')

    d = sub.add_parser('pdf', help='copy out a stored PDF after an integrity check')
    d.add_argument('serial')
    d.add_argument('--out', default=None)

    c = sub.add_parser('check-pdf', help='is this file one we issued, unchanged?')
    c.add_argument('file')

    s = sub.add_parser('serve', help='run the web app and API')
    s.add_argument('--host', default='127.0.0.1')
    s.add_argument('--port', type=int, default=5000)
    return p


def main(argv=None, env=None, out=None):
    out = out or sys.stdout
    args = build_parser().parse_args(argv)

    def say(*parts):
        print(*parts, file=out)

    if args.command == 'genkey':
        key, token = secrets.token_hex(32), secrets.token_urlsafe(32)
        say('# Add these to your shell (keep them secret, never commit them):')
        say(f'export CRED_KEYS={args.id}:{key}')
        say(f'export ADMIN_API_TOKEN={token}')
        say('# PowerShell:')
        say(f'$env:CRED_KEYS = "{args.id}:{key}"')
        say(f'$env:ADMIN_API_TOKEN = "{token}"')
        return 0

    try:
        service = Service.from_env(env)
        return run(args, service, say, env)
    except (ConfigError, CredentialError) as e:
        print(f'error: {e}', file=sys.stderr)
        return 2 if isinstance(e, ConfigError) else 1


def run(args, service, say, env):
    if args.command == 'issue':
        c = service.issue(holder_name=args.name, credential_type=args.ctype, holder_org=args.org,
                          purpose=args.purpose, valid_days=args.days, base_url=args.base_url)
        say(f'Issued    {c.serial}  ({c.credential_type}, valid until {c.expires_at})')
        say(f'Token     {c.token}')
        say(f'Verify    {service.verify_url(c.token, args.base_url)}')
        say(f'PDF       {service.issued_dir / c.pdf_file}')
        say(f'SHA-256   {c.pdf_sha256}')
        return 0

    if args.command == 'verify':
        res = service.verify(args.token, source='cli')
        say(res.state.upper().replace('_', ' '))
        if res.credential:
            c = res.credential
            say(f'{c.serial}  {c.holder_name}  ({c.credential_type})  valid until {c.expires_at}')
        return 0 if res.state == 'valid' else 1

    if args.command == 'revoke':
        c = service.revoke(args.serial, args.reason)
        say(f'{c.serial} is now {c.status}')
        return 0

    if args.command == 'list':
        for c in service.store.list_credentials():
            say(f'{c.serial}  {c.credential_type:<10} {c.status:<8} {c.expires_at}  {c.holder_name}')
        return 0

    if args.command == 'audit':
        rows = service.audit()
        for r in rows:
            say(f'{r.serial}  {r.result}')
        bad = [r for r in rows if r.result != 'ok']
        say(f'{len(rows)} checked, {len(bad)} failed')
        return 1 if bad else 0

    if args.command == 'pdf':
        try:
            data = service.read_pdf(args.serial)
        except IntegrityError as e:
            print(f'error: {e}. File not copied.', file=sys.stderr)
            return 1
        target = Path(args.out or f'{args.serial}.pdf')
        target.write_bytes(data)
        say(f'Wrote {target} ({len(data)} bytes, integrity OK)')
        return 0

    if args.command == 'check-pdf':
        with open(args.file, 'rb') as f:
            check = service.check_pdf(f.read(MAX_PDF_BYTES + 1))
        if check.kind == 'invalid':
            say('NOT CHECKED: not a PDF, empty, or larger than 2 MB')
            return 1
        if check.kind == 'nomatch':
            say('NO MATCH: not identical to any issued document')
            return 1
        say(f'MATCH: identical to {check.credential.serial} ({check.state.upper()})')
        return 0 if check.state == 'valid' else 1

    if args.command == 'serve':
        from .web import create_app
        create_app(service, load_admin_token(env)).run(host=args.host, port=args.port)
        return 0
    return 2
