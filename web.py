"""Flask app: public verification pages and API, plus a token-protected admin API."""
import hmac
import io
import time
from collections import defaultdict, deque
from functools import wraps

from flask import Flask, abort, jsonify, redirect, render_template, request, send_file, url_for

from . import pdfgen
from .config import load_admin_token
from .service import (MAX_PDF_BYTES, CredentialError, IntegrityError, NotFoundError,
                      Service, ValidationError)

TYPE_LABELS = {'membership': 'Certificate of Membership', 'noc': 'No Objection Certificate',
               'approval': 'Letter of Approval'}


class RateLimiter:
    """In-memory sliding window, per key. Fine for one process; use a shared store at scale."""

    def __init__(self):
        self._hits = defaultdict(deque)

    def limited(self, key, limit, window=60):
        now = time.time()
        q = self._hits[key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return True
        q.append(now)
        return False


def public_view(cred, state):
    """Only what a stranger scanning the QR code needs. No token, hash or file path."""
    return {'state': state, 'serial': cred.serial, 'type': cred.credential_type,
            'holder_name': cred.holder_name, 'holder_org': cred.holder_org,
            'purpose': cred.purpose, 'issued_at': cred.issued_at[:10],
            'expires_at': cred.expires_at}


def create_app(service: Service, admin_token=None, verify_limit=60, pdf_limit=10, admin_limit=20):
    app = Flask(__name__)
    app.config['MAX_CONTENT_LENGTH'] = MAX_PDF_BYTES + 16 * 1024
    app.jinja_env.globals['type_labels'] = TYPE_LABELS
    limiter = RateLimiter()

    def ip():
        return request.remote_addr or 'unknown'

    def throttle(bucket, limit):
        if limiter.limited(f'{ip()}:{bucket}', limit):
            abort(429)

    def link_base():
        # a configured BASE_URL wins; otherwise use the address the request came to
        return None if service.base_url else request.url_root

    @app.after_request
    def headers(resp):
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['Referrer-Policy'] = 'no-referrer'
        resp.headers['Content-Security-Policy'] = (
            "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        resp.headers['Cache-Control'] = 'no-store'   # revocation must show immediately
        return resp

    # ---------------- public pages ----------------
    @app.get('/')
    def index():
        code = request.args.get('code', '').strip()
        if code:
            return redirect(url_for('verify_page', token=code))
        return render_template('index.html', result=None, pdf=None)

    @app.get('/verify/<token>')
    def verify_page(token):
        throttle('verify', verify_limit)
        return render_template('index.html', result=service.verify(token, source=ip()), pdf=None)

    @app.get('/qr/<token>.png')
    def qr(token):
        throttle('verify', verify_limit)
        if service.lookup(token).credential is None:
            abort(404)
        url = service.verify_url(token, link_base())
        return send_file(io.BytesIO(pdfgen.qr_png_bytes(url)), mimetype='image/png')

    def run_pdf_check():
        throttle('pdf', pdf_limit)
        upload = request.files.get('pdf')
        data = upload.read(MAX_PDF_BYTES + 1) if upload else b''
        return service.check_pdf(data)

    @app.post('/check-pdf')
    def check_pdf_page():
        check = run_pdf_check()
        return render_template('index.html', result=None, pdf=check), (400 if check.kind == 'invalid' else 200)

    # ---------------- public API ----------------
    @app.get('/api/verify/<token>')
    def api_verify(token):
        throttle('verify', verify_limit)
        result = service.verify(token, source=ip())
        if result.credential is None:
            return jsonify(state='not_found'), 404
        return jsonify(public_view(result.credential, result.state))

    @app.post('/api/check-pdf')
    def api_check_pdf():
        check = run_pdf_check()
        body = {'result': check.kind}
        if check.kind == 'match':
            body.update(public_view(check.credential, check.state))
        return jsonify(body), (400 if check.kind == 'invalid' else 200)

    # ---------------- admin API (bearer token) ----------------
    def admin_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if admin_token is None:
                abort(404)           # admin API disabled
            throttle('admin', admin_limit)
            scheme, _, supplied = request.headers.get('Authorization', '').partition(' ')
            if scheme.lower() != 'bearer' or not hmac.compare_digest(
                    supplied.strip().encode(), admin_token.encode()):
                return jsonify(error='unauthorized'), 401, {'WWW-Authenticate': 'Bearer'}
            return view(*args, **kwargs)
        return wrapped

    @app.post('/api/credentials')
    @admin_required
    def api_issue():
        body = request.get_json(silent=True)
        if not isinstance(body, dict):
            raise ValidationError('send a JSON object')
        cred = service.issue(
            holder_name=body.get('holder_name', ''), credential_type=body.get('credential_type', ''),
            holder_org=body.get('holder_org', ''), purpose=body.get('purpose', ''),
            valid_days=body.get('valid_days', 365), base_url=link_base())
        return jsonify(serial=cred.serial, token=cred.token, expires_at=cred.expires_at,
                       verify_url=service.verify_url(cred.token, link_base()),
                       pdf_url=url_for('api_pdf', serial=cred.serial)), 201

    @app.post('/api/credentials/<serial>/revoke')
    @admin_required
    def api_revoke(serial):
        body = request.get_json(silent=True) or {}
        cred = service.revoke(serial, str(body.get('reason', '')))
        return jsonify(serial=cred.serial, status=cred.status)

    @app.get('/api/credentials/<serial>/pdf')
    @admin_required
    def api_pdf(serial):
        data = service.read_pdf(serial)       # raises IntegrityError on a changed or missing file
        return send_file(io.BytesIO(data), mimetype='application/pdf', as_attachment=True,
                         download_name=f'{serial}.pdf')

    @app.get('/api/audit')
    @admin_required
    def api_audit():
        rows = service.audit()
        return jsonify(ok=all(r.result == 'ok' for r in rows),
                       results=[{'serial': r.serial, 'result': r.result} for r in rows])

    # ---------------- errors ----------------
    @app.errorhandler(ValidationError)
    def bad_input(e):
        return jsonify(error=str(e)), 400

    @app.errorhandler(NotFoundError)
    def not_found(e):
        return jsonify(error=str(e)), 404

    @app.errorhandler(IntegrityError)
    def integrity(e):
        return jsonify(error='integrity_check_failed', reason=e.reason, serial=e.serial), 409

    @app.errorhandler(413)
    def too_large(e):
        if request.path.startswith('/api/'):
            return jsonify(error='file too large (max 2 MB)'), 413
        from .service import PdfCheck
        return render_template('index.html', result=None, pdf=PdfCheck('invalid')), 413

    @app.errorhandler(429)
    def slow_down(e):
        return jsonify(error='too many requests, try again in a minute'), 429

    return app


def create_app_from_env(env=None):
    return create_app(Service.from_env(env), load_admin_token(env))
