"""Issue, verify, revoke and audit credentials."""
import hashlib
import hmac
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import pdfgen, tokens
from .config import load_keyring
from .store import Store

MAX_PDF_BYTES = 2 * 1024 * 1024
TYPES = {
    'membership': ('Certificate of Membership', 'is a registered member in good standing.'),
    'noc': ('No Objection Certificate', 'has no objection from the issuing body for: {purpose}'),
    'approval': ('Letter of Approval', 'has been approved for: {purpose}'),
}
FOOTER = 'Demonstration document from a learning prototype. Not an official document.'
_CONTROL = re.compile(r'[\x00-\x1f\x7f]')


class CredentialError(Exception):
    """Base class for expected, user-facing failures."""


class ValidationError(CredentialError):
    pass


class NotFoundError(CredentialError):
    pass


class IntegrityError(CredentialError):
    def __init__(self, reason, serial):
        super().__init__(f'integrity check failed for {serial}: {reason}')
        self.reason = reason
        self.serial = serial


@dataclass(frozen=True)
class VerifyResult:
    state: str            # valid | expired | revoked | not_found
    credential: object = None


@dataclass(frozen=True)
class PdfCheck:
    kind: str             # invalid | nomatch | match
    credential: object = None
    state: str = ''


@dataclass(frozen=True)
class AuditRow:
    serial: str
    result: str           # ok | mismatch | missing


def effective_state(cred, today):
    if cred.status == 'revoked':
        return 'revoked'
    if cred.expires_at < today:
        return 'expired'
    return 'valid'


def _clean(text, limit):
    return _CONTROL.sub(' ', (text or '')).strip()[:limit]


class Service:
    def __init__(self, store, keyring, issued_dir, base_url='', clock=None):
        self.store = store
        self.keyring = keyring
        self.issued_dir = Path(issued_dir)
        self.base_url = base_url.rstrip('/')
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.issued_dir.mkdir(parents=True, exist_ok=True)
        self.store.init_schema()

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env
        data_dir = Path(env.get('CRED_DATA_DIR', 'data'))
        data_dir.mkdir(parents=True, exist_ok=True)
        return cls(Store(data_dir / 'credentials.db'), load_keyring(env),
                   data_dir / 'issued', env.get('BASE_URL', ''))

    # ---------- helpers ----------
    def verify_url(self, token, base_url=None):
        base = (base_url or self.base_url or 'http://127.0.0.1:5000').rstrip('/')
        return f'{base}/verify/{token}'

    def _pdf_path(self, cred):
        return self.issued_dir / os.path.basename(cred.pdf_file)

    def _write_atomic(self, path, data, written):
        """Write to a temp file, then rename, so a reader never sees a partial PDF."""
        tmp = path.with_name(path.name + '.tmp')
        written.extend([tmp, path])
        with open(tmp, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)

    # ---------- issue ----------
    def issue(self, *, holder_name, credential_type, holder_org='', purpose='',
              valid_days=365, base_url=None):
        name = _clean(holder_name, 120)
        org = _clean(holder_org, 160)
        purpose = _clean(purpose, 255)
        if len(name) < 2:
            raise ValidationError('holder name must be 2-120 characters')
        if credential_type not in TYPES:
            raise ValidationError(f'credential type must be one of: {", ".join(TYPES)}')
        if credential_type != 'membership' and not purpose:
            raise ValidationError('a purpose is required for this credential type')
        if isinstance(valid_days, bool) or not isinstance(valid_days, int) or not 1 <= valid_days <= 3650:
            raise ValidationError('valid_days must be a whole number between 1 and 3650')

        now = self.clock()
        title, template = TYPES[credential_type]
        statement = template.format(purpose=purpose)
        issued_at = now.strftime('%Y-%m-%dT%H:%M:%SZ')
        expires = (now + timedelta(days=valid_days)).strftime('%Y-%m-%d')

        written = []
        try:
            with self.store.transaction() as conn:
                number = self.store.next_number(conn)
                serial = f'CRD-{now.year}-{number:06d}'
                token = tokens.make_token(self.keyring)
                key_id = token.split('.')[0]
                pdf = pdfgen.render(
                    title=title, serial=serial, holder_name=name, holder_org=org,
                    statement=statement, issued=issued_at[:10], expires=expires,
                    token=token, link=self.verify_url(token, base_url), key_id=key_id,
                    footer=FOOTER)
                digest = hashlib.sha256(pdf).hexdigest()
                file_name = f'{serial}.pdf'
                self.store.insert(
                    conn, id=number, serial=serial, token=token, key_id=key_id,
                    credential_type=credential_type, holder_name=name, holder_org=org,
                    purpose=purpose, issued_at=issued_at, expires_at=expires,
                    pdf_file=file_name, pdf_sha256=digest)
                self._write_atomic(self.issued_dir / file_name, pdf, written)
                self.store.add_event(conn, number, 'issued', f'key={key_id}')
        except BaseException:
            for p in written:        # nothing is committed, so leave no file behind
                try:
                    os.remove(p)
                except OSError:
                    pass
            raise
        return self.store.get_by_serial(serial)

    # ---------- verify ----------
    def lookup(self, token):
        """Signature first (no database), then the database. No event is recorded."""
        if tokens.parse_token(self.keyring, token) is None:
            return VerifyResult('not_found')
        cred = self.store.get_by_token(token)
        if cred is None:
            return VerifyResult('not_found')
        return VerifyResult(effective_state(cred, self.clock().strftime('%Y-%m-%d')), cred)

    def verify(self, token, source=''):
        result = self.lookup(token)
        if result.credential:
            with self.store.transaction() as conn:
                self.store.add_event(conn, result.credential.id, 'verified', source)
        return result

    # ---------- revoke ----------
    def revoke(self, serial, reason=''):
        cred = self.store.get_by_serial(serial)
        if cred is None:
            raise NotFoundError(f'no credential {serial}')
        with self.store.transaction() as conn:
            self.store.set_revoked(conn, serial)
            self.store.add_event(conn, cred.id, 'revoked', _clean(reason, 150))
        return self.store.get_by_serial(serial)

    # ---------- integrity ----------
    def _check_file(self, cred):
        """Return (result, bytes_or_None); result is ok, mismatch or missing."""
        try:
            data = self._pdf_path(cred).read_bytes()
        except OSError:
            return 'missing', None
        actual = hashlib.sha256(data).hexdigest()
        ok = hmac.compare_digest(actual, cred.pdf_sha256)
        return ('ok' if ok else 'mismatch'), data

    def _record_failure(self, cred, result):
        with self.store.transaction() as conn:
            self.store.add_event(conn, cred.id, 'integrity_failed', result)

    def read_pdf(self, serial):
        """The stored PDF, but only if its SHA-256 still matches what was recorded."""
        cred = self.store.get_by_serial(serial)
        if cred is None:
            raise NotFoundError(f'no credential {serial}')
        result, data = self._check_file(cred)
        if result != 'ok':
            self._record_failure(cred, result)
            raise IntegrityError(result, serial)
        return data

    def audit(self):
        rows = []
        for cred in self.store.list_credentials():
            result, _ = self._check_file(cred)
            if result != 'ok':
                self._record_failure(cred, result)
            rows.append(AuditRow(cred.serial, result))
        return rows

    def check_pdf(self, data):
        """Is this uploaded file byte-for-byte one that we issued?"""
        if not data or len(data) > MAX_PDF_BYTES or not data.startswith(b'%PDF'):
            return PdfCheck('invalid')
        cred = self.store.get_by_hash(hashlib.sha256(data).hexdigest())
        if cred is None:
            return PdfCheck('nomatch')
        with self.store.transaction() as conn:
            self.store.add_event(conn, cred.id, 'pdf_checked')
        return PdfCheck('match', cred, effective_state(cred, self.clock().strftime('%Y-%m-%d')))
