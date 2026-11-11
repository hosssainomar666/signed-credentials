"""HMAC-signed credential tokens.

Format:  <key id>.<random id>.<signature>
  key id     which signing key made it (allows key rotation)
  random id  96 random bits, the public handle looked up in the database
  signature  first 16 bytes of HMAC-SHA256(key, domain | key id | random id), base64url

A token can be checked for authenticity with no database access, so forged
tokens never reach the database.
"""
import base64
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass

from .config import KID_RE

RID_RE = re.compile(r'[A-Za-z0-9_-]{16}')   # token_urlsafe(12) is always 16 characters
SIG_RE = re.compile(r'[A-Za-z0-9_-]{22}')   # 16 bytes in base64url, no padding
DOMAIN = b'credential-token-v1'
MAX_TOKEN_LEN = 64


@dataclass(frozen=True)
class ParsedToken:
    key_id: str
    random_id: str


def _signature(secret, key_id, random_id):
    message = b'|'.join([DOMAIN, key_id.encode(), random_id.encode()])
    mac = hmac.new(secret, message, hashlib.sha256).digest()[:16]
    return base64.urlsafe_b64encode(mac).rstrip(b'=').decode()


def make_token(keyring, *, key_id=None):
    kid = key_id or keyring.active
    random_id = secrets.token_urlsafe(12)
    return f'{kid}.{random_id}.{_signature(keyring.keys[kid], kid, random_id)}'


def parse_token(keyring, token):
    """Return ParsedToken if the token is well formed and correctly signed, else None."""
    if not isinstance(token, str) or not token.isascii() or len(token) > MAX_TOKEN_LEN:
        return None
    parts = token.split('.')
    if len(parts) != 3:
        return None
    kid, random_id, sig = parts
    # fullmatch, not match: '$' would accept a trailing newline
    if not (KID_RE.fullmatch(kid) and RID_RE.fullmatch(random_id) and SIG_RE.fullmatch(sig)):
        return None
    secret = keyring.keys.get(kid)
    if secret is None:   # unknown or retired key
        return None
    expected = _signature(secret, kid, random_id)
    if not hmac.compare_digest(sig.encode(), expected.encode()):
        return None
    return ParsedToken(kid, random_id)
