import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr

from credentials.cli import main

KEYS = 'k1:' + 'c' * 40


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.env = {'CRED_KEYS': KEYS, 'CRED_DATA_DIR': os.path.join(self.tmp, 'data')}

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stderr(err):
            code = main(list(argv), env=self.env, out=out)
        return code, out.getvalue(), err.getvalue()

    def issue(self, *extra):
        code, out, _ = self.run_cli('issue', '--name', 'Test Holder', '--type', 'membership', *extra)
        self.assertEqual(code, 0, out)
        token = next(l for l in out.splitlines() if l.startswith('Token')).split()[1]
        serial = out.split()[1]
        return serial, token

    def test_genkey_output_is_usable(self):
        code, out, _ = self.run_cli('genkey', '--id', 'k9')
        self.assertEqual(code, 0)
        line = next(l for l in out.splitlines() if l.startswith('export CRED_KEYS='))
        from credentials.config import load_keyring
        self.assertEqual(load_keyring({'CRED_KEYS': line.split('=', 1)[1]}).active, 'k9')

    def test_missing_key_is_a_clear_error(self):
        self.env.pop('CRED_KEYS')
        code, _, err = self.run_cli('list')
        self.assertEqual(code, 2)
        self.assertIn('CRED_KEYS', err)

    def test_issue_verify_revoke_flow(self):
        serial, token = self.issue()
        self.assertEqual(self.run_cli('verify', token)[0], 0)
        self.assertIn(serial, self.run_cli('list')[1])
        self.assertEqual(self.run_cli('revoke', serial, '--reason', 'test')[0], 0)
        code, out, _ = self.run_cli('verify', token)
        self.assertEqual((code, out.split()[0]), (1, 'REVOKED'))

    def test_verify_rejects_garbage(self):
        code, out, _ = self.run_cli('verify', 'garbage')
        self.assertEqual((code, out.strip()), (1, 'NOT FOUND'))

    def test_validation_error_exit_code(self):
        code, _, err = self.run_cli('issue', '--name', 'Test Holder', '--type', 'noc')
        self.assertEqual(code, 1)
        self.assertIn('purpose', err)

    def test_audit_pdf_and_check_pdf(self):
        serial, _ = self.issue()
        self.assertEqual(self.run_cli('audit')[0], 0)
        out_file = os.path.join(self.tmp, 'copy.pdf')
        self.assertEqual(self.run_cli('pdf', serial, '--out', out_file)[0], 0)
        self.assertEqual(self.run_cli('check-pdf', out_file)[0], 0)
        with open(out_file, 'ab') as f:
            f.write(b'\n% edited')
        self.assertEqual(self.run_cli('check-pdf', out_file)[0], 1)
        # tamper with the stored file: audit and pdf both fail
        stored = os.path.join(self.tmp, 'data', 'issued', f'{serial}.pdf')
        with open(stored, 'ab') as f:
            f.write(b'x')
        code, out, _ = self.run_cli('audit')
        self.assertEqual(code, 1)
        self.assertIn('mismatch', out)
        code, _, err = self.run_cli('pdf', serial, '--out', os.path.join(self.tmp, 'bad.pdf'))
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'bad.pdf')))


if __name__ == '__main__':
    unittest.main()
