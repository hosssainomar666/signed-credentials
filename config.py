"""Configuration and key loading. Secrets come from the environment only."""
import os
import re
import secrets
import sys
from dataclasses import dataclass

KID_RE = re.compile(r'[A-Za-z0-9]{1,8}')
MIN_KEY_BYTES = 32
MIN_ADMIN_TOKEN_BYTES = 24


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Keyring:
    """Signing keys by id. New tokens use `active`; older keys stay so that
    tokens they signed keep verifying until the key is retired."""
    keys: dict
    active: str


def _dev_mode(env):
    return env.get('APP_ENV', 'production').lower() in ('development', 'test')


def load_keyring(env=None):
    """Read CRED_KEYS="k1:<secret>,k2:<secret>" and CRED_ACTIVE_KEY.

    Refuses to start (outside development/test) when no key is configured.
    Any configured key must be at least 32 bytes and keys must be distinct."""
    env = os.environ if env is None else env
    raw = env.get('CRED_KEYS', '').strip()
    if not raw:
        if not _dev_mode(env):
            raise ConfigError(
                'CRED_KEYS is not set. Generate one with: python -m credentials genkey')
        print('WARNING: CRED_KEYS not set; using a random throwaway key. '
              'Credentials issued now will not verify after a restart.', file=sys.stderr)
        return Keyring({'dev': secrets.token_bytes(32)}, 'dev')

    keys = {}
    for part in raw.split(','):
        kid, sep, secret = part.strip().partition(':')
        if not sep or not KID_RE.fullmatch(kid):
            raise ConfigError('CRED_KEYS entries look like id:secret, with an id of 1-8 letters or digits')
        if kid in keys:
            raise ConfigError(f'duplicate key id {kid!r}')
        if len(secret.encode()) < MIN_KEY_BYTES:
            raise ConfigError(f'key {kid!r} is shorter than {MIN_KEY_BYTES} bytes')
        keys[kid] = secret.encode()
    if len(set(keys.values())) != len(keys):
        raise ConfigError('two key ids share the same secret')

    active = env.get('CRED_ACTIVE_KEY', '').strip()
    if not active:
        if len(keys) != 1:
            raise ConfigError('set CRED_ACTIVE_KEY when several keys are configured')
        active = next(iter(keys))
    if active not in keys:
        raise ConfigError(f'CRED_ACTIVE_KEY {active!r} is not in CRED_KEYS')
    return Keyring(keys, active)


def load_admin_token(env=None):
    """Bearer token for the admin API, or None when the admin API is disabled."""
    env = os.environ if env is None else env
    token = env.get('ADMIN_API_TOKEN', '')
    if not token:
        return None
    if len(token.encode()) < MIN_ADMIN_TOKEN_BYTES:
        raise ConfigError(f'ADMIN_API_TOKEN is shorter than {MIN_ADMIN_TOKEN_BYTES} bytes')
    return token
