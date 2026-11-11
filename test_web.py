import io
import unittest

from credentials.web import create_app
from tests.helpers import make_service, issue_member

ADMIN = 'admin-token-' + 'x' * 20
AUTH = {'Authorization': f'Bearer {ADMIN}'}


class WebBase(unittest.TestCase):
    def setUp(self):
        self.s = make_service(base_url='')
        self.app = create_app(self.s, ADMIN)
        self.c = self.app.test_client()
        self.cred = issue_member(self.s, name='Rahim Uddin', org='Solar Ltd')

    def upload(self, data, path='/check-pdf', name='f.pdf'):
        return self.c.post(path, data={'pdf': (io.BytesIO(data), name)},
                           content_type='multipart/form-data')


class PublicTests(WebBase):
    def test_index_and_code_redirect(self):
        self.assertEqual(self.c.get('/').status_code, 200)
        r = self.c.get('/', query_string={'code': self.cred.token})
        self.assertEqual(r.status_code, 302)
        self.assertIn('/verify/', r.headers['Location'])

    def test_verify_page_states(self):
        page = self.c.get(f'/verify/{self.cred.token}').get_data(as_text=True)
        self.assertIn('VALID', page)
        self.assertIn('Rahim Uddin', page)
        self.s.revoke(self.cred.serial)
        self.assertIn('REVOKED', self.c.get(f'/verify/{self.cred.token}').get_data(as_text=True))
        self.assertIn('NOT FOUND', self.c.get('/verify/not-a-token').get_data(as_text=True))

    def test_api_verify_hides_internal_fields(self):
        r = self.c.get(f'/api/verify/{self.cred.token}')
        body = r.get_json()
        self.assertEqual((r.status_code, body['state'], body['serial']), (200, 'valid', self.cred.serial))
        for secret in ('token', 'pdf_sha256', 'pdf_file', 'id', 'key_id'):
            self.assertNotIn(secret, body)
        self.assertEqual(self.c.get('/api/verify/nope').status_code, 404)

    def test_xss_in_holder_name_is_escaped(self):
        c = self.s.issue(holder_name='<script>alert(1)</script>', credential_type='membership')
        page = self.c.get(f'/verify/{c.token}').get_data(as_text=True)
        self.assertNotIn('<script>alert(1)</script>', page)
        self.assertIn('&lt;script&gt;', page)

    def test_qr_png(self):
        r = self.c.get(f'/qr/{self.cred.token}.png')
        self.assertEqual((r.status_code, r.mimetype), (200, 'image/png'))
        self.assertTrue(r.data.startswith(b'\x89PNG'))
        self.assertEqual(self.c.get('/qr/forged.png').status_code, 404)

    def test_pdf_check_page_and_api(self):
        original = (self.s.issued_dir / self.cred.pdf_file).read_bytes()
        self.assertIn('byte-for-byte identical', self.upload(original).get_data(as_text=True))
        self.assertIn('NO MATCH', self.upload(original + b'x').get_data(as_text=True))
        self.assertEqual(self.upload(b'hello').status_code, 400)
        big = b'%PDF' + b'0' * (3 * 1024 * 1024)
        self.assertEqual(self.upload(big).status_code, 413)
        api = self.upload(original, '/api/check-pdf')
        self.assertEqual((api.status_code, api.get_json()['result']), (200, 'match'))
        self.assertEqual(self.upload(big, '/api/check-pdf').status_code, 413)

    def test_security_headers(self):
        h = self.c.get('/').headers
        self.assertEqual(h['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(h['X-Frame-Options'], 'DENY')
        self.assertIn("default-src 'none'", h['Content-Security-Policy'])
        self.assertEqual(h['Cache-Control'], 'no-store')

    def test_rate_limits(self):
        app = create_app(self.s, ADMIN, verify_limit=3, pdf_limit=2, admin_limit=3)
        c = app.test_client()
        codes = [c.get(f'/api/verify/{self.cred.token}').status_code for _ in range(5)]
        self.assertEqual(codes, [200, 200, 200, 429, 429])
        pdf = [c.post('/api/check-pdf', data={'pdf': (io.BytesIO(b'x'), 'f.pdf')},
                      content_type='multipart/form-data').status_code for _ in range(3)]
        self.assertEqual(pdf, [400, 400, 429])
        auth = [c.get('/api/audit', headers={'Authorization': 'Bearer wrong'}).status_code
                for _ in range(5)]
        self.assertEqual(auth, [401, 401, 401, 429, 429])


class AdminApiTests(WebBase):
    def test_admin_api_disabled_without_token(self):
        c = create_app(self.s, None).test_client()
        self.assertEqual(c.get('/api/audit', headers=AUTH).status_code, 404)

    def test_requires_correct_bearer_token(self):
        for headers in ({}, {'Authorization': 'Bearer wrong'}, {'Authorization': ADMIN},
                        {'Authorization': f'Basic {ADMIN}'}):
            r = self.c.post('/api/credentials', json={'holder_name': 'X Y', 'credential_type': 'membership'},
                            headers=headers)
            self.assertEqual(r.status_code, 401, headers)
        self.assertEqual(len(self.s.store.list_credentials()), 1)      # nothing was issued

    def test_issue_verify_download_revoke(self):
        r = self.c.post('/api/credentials', headers=AUTH, json={
            'holder_name': 'Nusrat Jahan', 'credential_type': 'noc',
            'purpose': 'Tender submission', 'valid_days': 30})
        self.assertEqual(r.status_code, 201)
        body = r.get_json()
        self.assertTrue(body['verify_url'].startswith('http://localhost/verify/'))
        self.assertEqual(self.c.get(f"/api/verify/{body['token']}").get_json()['state'], 'valid')
        pdf = self.c.get(body['pdf_url'], headers=AUTH)
        self.assertEqual((pdf.status_code, pdf.mimetype), (200, 'application/pdf'))
        self.assertTrue(pdf.data.startswith(b'%PDF'))
        rv = self.c.post(f"/api/credentials/{body['serial']}/revoke", headers=AUTH, json={'reason': 'test'})
        self.assertEqual(rv.get_json()['status'], 'revoked')
        self.assertEqual(self.c.get(f"/api/verify/{body['token']}").get_json()['state'], 'revoked')

    def test_validation_errors_are_400(self):
        for payload in ({}, {'holder_name': 'X Y', 'credential_type': 'noc'},
                        {'holder_name': 'X Y', 'credential_type': 'membership', 'valid_days': 'abc'}):
            r = self.c.post('/api/credentials', headers=AUTH, json=payload)
            self.assertEqual(r.status_code, 400, payload)
        self.assertEqual(self.c.post('/api/credentials', headers=AUTH, data='nope',
                                     content_type='text/plain').status_code, 400)

    def test_tampered_pdf_is_refused_with_409_and_audit_reports_it(self):
        path = self.s.issued_dir / self.cred.pdf_file
        path.write_bytes(path.read_bytes() + b'\n% tampered')
        r = self.c.get(f'/api/credentials/{self.cred.serial}/pdf', headers=AUTH)
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.get_json()['reason'], 'mismatch')
        self.assertFalse(r.data.startswith(b'%PDF'))
        audit = self.c.get('/api/audit', headers=AUTH).get_json()
        self.assertFalse(audit['ok'])
        self.assertEqual(audit['results'][0]['result'], 'mismatch')

    def test_unknown_serial_is_404(self):
        self.assertEqual(self.c.get('/api/credentials/CRD-2026-999999/pdf', headers=AUTH).status_code, 404)
        self.assertEqual(self.c.post('/api/credentials/CRD-2026-999999/revoke', headers=AUTH).status_code, 404)


if __name__ == '__main__':
    unittest.main()
