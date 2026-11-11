import hashlib
import os
import tempfile
import threading
import unittest
from datetime import timedelta
from unittest import mock

from credentials import tokens
from credentials.config import Keyring
from credentials.service import (MAX_PDF_BYTES, IntegrityError, NotFoundError, Service,
                                 ValidationError)
from credentials.store import Store
from tests.helpers import KEY_A, KEY_B, Clock, issue_member, keyring, make_service


class IssueTests(unittest.TestCase):
    def setUp(self):
        self.s = make_service()

    def test_issue_creates_row_pdf_and_matching_hash(self):
        c = issue_member(self.s)
        self.assertRegex(c.serial, r'^CRD-2026-\d{6}$')
        data = (self.s.issued_dir / c.pdf_file).read_bytes()
        self.assertTrue(data.startswith(b'%PDF'))
        self.assertEqual(hashlib.sha256(data).hexdigest(), c.pdf_sha256)
        self.assertIsNotNone(tokens.parse_token(self.s.keyring, c.token))
        self.assertEqual(self.s.store.count_events('issued', c.id), 1)

    def test_serials_increase_and_files_are_separate(self):
        a, b = issue_member(self.s), issue_member(self.s)
        self.assertNotEqual(a.serial, b.serial)
        self.assertNotEqual(a.pdf_sha256, b.pdf_sha256)

    def test_validation(self):
        bad = [dict(holder_name='', credential_type='membership'),
               dict(holder_name='X', credential_type='membership'),
               dict(holder_name='Valid Name', credential_type='unknown'),
               dict(holder_name='Valid Name', credential_type='noc'),            # purpose required
               dict(holder_name='Valid Name', credential_type='membership', valid_days=0),
               dict(holder_name='Valid Name', credential_type='membership', valid_days=99999),
               dict(holder_name='Valid Name', credential_type='membership', valid_days=True),
               dict(holder_name='Valid Name', credential_type='membership', valid_days='30')]
        for kw in bad:
            with self.assertRaises(ValidationError, msg=kw):
                self.s.issue(**kw)
        self.assertEqual(self.s.store.list_credentials(), [])

    def test_control_characters_are_stripped(self):
        c = self.s.issue(holder_name='Line\nBreak\x00 Name', credential_type='membership')
        self.assertEqual(c.holder_name, 'Line Break  Name')

    def test_non_latin_names_do_not_break_pdf_generation(self):
        c = self.s.issue(holder_name='\u09b0\u09b9\u09bf\u09ae Uddin', credential_type='membership')
        self.assertTrue((self.s.issued_dir / c.pdf_file).read_bytes().startswith(b'%PDF'))

    def test_pdf_failure_leaves_no_row_and_no_file(self):
        with mock.patch('credentials.service.pdfgen.render', side_effect=RuntimeError('boom')):
            with self.assertRaises(RuntimeError):
                issue_member(self.s)
        self.assertEqual(self.s.store.list_credentials(), [])
        self.assertEqual(os.listdir(self.s.issued_dir), [])

    def test_failure_after_file_is_written_rolls_back_and_removes_files(self):
        with mock.patch.object(Store, 'add_event', side_effect=RuntimeError('after write')):
            with self.assertRaises(RuntimeError):
                issue_member(self.s)
        self.assertEqual(self.s.store.list_credentials(), [])
        self.assertEqual(os.listdir(self.s.issued_dir), [])      # no pdf and no .tmp file
        self.assertIsNotNone(issue_member(self.s))               # and issuing still works

    def test_concurrent_issuing_gives_unique_serials(self):
        errors, made = [], []

        def work():
            try:
                for _ in range(5):
                    made.append(issue_member(self.s))
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=work) for _ in range(8)]
        [t.start() for t in threads]
        [t.join() for t in threads]
        self.assertEqual(errors, [])
        self.assertEqual(len({c.serial for c in made}), 40)
        self.assertTrue(all(r.result == 'ok' for r in self.s.audit()))


class VerifyTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.s = make_service(clock=self.clock)

    def test_states(self):
        c = issue_member(self.s, valid_days=10)
        self.assertEqual(self.s.verify(c.token).state, 'valid')
        self.clock.now += timedelta(days=10)
        self.assertEqual(self.s.verify(c.token).state, 'valid')      # last valid day
        self.clock.now += timedelta(days=1)
        self.assertEqual(self.s.verify(c.token).state, 'expired')
        self.s.revoke(c.serial, 'test')
        self.assertEqual(self.s.verify(c.token).state, 'revoked')    # revoked wins over expired

    def test_unknown_but_correctly_signed_token_is_not_found(self):
        self.assertEqual(self.s.verify(tokens.make_token(self.s.keyring)).state, 'not_found')

    def test_forged_token_never_touches_the_database(self):
        forged = tokens.make_token(keyring(('k1', KEY_B)))
        with mock.patch.object(Store, 'get_by_token', side_effect=AssertionError('DB used')):
            self.assertEqual(self.s.verify(forged).state, 'not_found')
            self.assertEqual(self.s.verify('garbage').state, 'not_found')

    def test_verify_records_an_event_but_lookup_does_not(self):
        c = issue_member(self.s)
        self.s.lookup(c.token)
        self.assertEqual(self.s.store.count_events('verified', c.id), 0)
        self.s.verify(c.token, source='1.2.3.4')
        self.assertEqual(self.s.store.count_events('verified', c.id), 1)

    def test_revoke_unknown_serial(self):
        with self.assertRaises(NotFoundError):
            self.s.revoke('CRD-2026-999999')

    def test_key_rotation(self):
        old = issue_member(self.s)
        rotated = Service(self.s.store, Keyring({'k1': KEY_A, 'k2': KEY_B}, 'k2'),
                          self.s.issued_dir, clock=self.clock)
        new = issue_member(rotated)
        self.assertEqual((old.key_id, new.key_id), ('k1', 'k2'))
        self.assertEqual(rotated.verify(old.token).state, 'valid')
        self.assertEqual(rotated.verify(new.token).state, 'valid')
        retired = Service(self.s.store, Keyring({'k2': KEY_B}, 'k2'), self.s.issued_dir,
                          clock=self.clock)
        self.assertEqual(retired.verify(old.token).state, 'not_found')


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.s = make_service()
        self.c = issue_member(self.s)
        self.path = self.s.issued_dir / self.c.pdf_file

    def test_read_pdf_returns_stored_bytes(self):
        self.assertEqual(hashlib.sha256(self.s.read_pdf(self.c.serial)).hexdigest(),
                         self.c.pdf_sha256)

    def test_modified_file_is_refused_and_logged(self):
        self.path.write_bytes(self.path.read_bytes() + b'\n% tampered')
        with self.assertRaises(IntegrityError) as ctx:
            self.s.read_pdf(self.c.serial)
        self.assertEqual(ctx.exception.reason, 'mismatch')
        self.assertEqual(self.s.store.count_events('integrity_failed', self.c.id), 1)

    def test_same_length_change_is_also_caught(self):
        data = bytearray(self.path.read_bytes())
        data[-5] ^= 0x01
        self.path.write_bytes(bytes(data))
        with self.assertRaises(IntegrityError):
            self.s.read_pdf(self.c.serial)

    def test_missing_file_is_refused(self):
        self.path.unlink()
        with self.assertRaises(IntegrityError) as ctx:
            self.s.read_pdf(self.c.serial)
        self.assertEqual(ctx.exception.reason, 'missing')

    def test_unknown_serial(self):
        with self.assertRaises(NotFoundError):
            self.s.read_pdf('CRD-2026-999999')

    def test_audit_flags_only_the_bad_files(self):
        good, tampered, gone = issue_member(self.s), issue_member(self.s), issue_member(self.s)
        p = self.s.issued_dir / tampered.pdf_file
        p.write_bytes(p.read_bytes() + b'x')
        (self.s.issued_dir / gone.pdf_file).unlink()
        results = {r.serial: r.result for r in self.s.audit()}
        self.assertEqual(results[self.c.serial], 'ok')
        self.assertEqual(results[good.serial], 'ok')
        self.assertEqual(results[tampered.serial], 'mismatch')
        self.assertEqual(results[gone.serial], 'missing')

    def test_check_pdf(self):
        original = self.path.read_bytes()
        m = self.s.check_pdf(original)
        self.assertEqual((m.kind, m.state, m.credential.serial), ('match', 'valid', self.c.serial))
        self.assertEqual(self.s.check_pdf(original + b'\n% edited').kind, 'nomatch')
        for bad in (b'', b'hello', b'%PDF' + b'0' * MAX_PDF_BYTES):
            self.assertEqual(self.s.check_pdf(bad).kind, 'invalid')
        self.s.revoke(self.c.serial)
        self.assertEqual(self.s.check_pdf(original).state, 'revoked')


if __name__ == '__main__':
    unittest.main()
