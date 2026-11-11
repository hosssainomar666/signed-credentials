import tempfile
from datetime import datetime, timezone
from pathlib import Path

from credentials.config import Keyring
from credentials.service import Service
from credentials.store import Store

KEY_A = b'a' * 40
KEY_B = b'b' * 40


def keyring(*pairs, active=None):
    keys = dict(pairs) or {'k1': KEY_A}
    return Keyring(keys, active or next(iter(keys)))


class Clock:
    """A clock the tests can move."""

    def __init__(self, when=None):
        self.now = when or datetime(2026, 11, 10, 12, 0, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


def make_service(tmp=None, kr=None, clock=None, base_url='http://test.local'):
    tmp = Path(tmp or tempfile.mkdtemp())
    return Service(Store(tmp / 'c.db'), kr or keyring(), tmp / 'issued', base_url,
                   clock=clock or Clock())


def issue_member(service, name='Test Holder', org='Test Org', **kw):
    return service.issue(holder_name=name, holder_org=org, credential_type='membership', **kw)
