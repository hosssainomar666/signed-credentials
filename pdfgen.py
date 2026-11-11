"""Render a credential as an A4 landscape PDF with an embedded QR code."""
import io

import qrcode
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.utils import ImageReader, simpleSplit
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas

GREEN = HexColor('#14532d')
INK = HexColor('#1f2933')
MUTED = HexColor('#52606d')


def qr_png_bytes(url):
    img = qrcode.make(url, error_correction=qrcode.constants.ERROR_CORRECT_M,
                      box_size=8, border=4)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    return buf.getvalue()


def _latin1(text):
    # The built-in PDF fonts only cover Latin-1; other characters print as '?'.
    return (text or '').encode('latin-1', 'replace').decode('latin-1')


def render(*, title, serial, holder_name, holder_org, statement, issued, expires,
           token, link, key_id, footer):
    """Return the PDF as bytes."""
    buf = io.BytesIO()
    width, height = landscape(A4)
    c = canvas.Canvas(buf, pagesize=(width, height))
    c.setTitle(f'{title} {serial}')
    c.setAuthor('Credential service')

    # frame
    c.setStrokeColor(GREEN)
    c.setLineWidth(3)
    c.rect(30, 30, width - 60, height - 60)
    c.setLineWidth(0.8)
    c.rect(38, 38, width - 76, height - 76)

    cx = width / 2
    c.setFillColor(GREEN)
    c.setFont('Helvetica-Bold', 30)
    c.drawCentredString(cx, height - 105, _latin1(title))
    c.setFillColor(MUTED)
    c.setFont('Helvetica', 12)
    c.drawCentredString(cx, height - 128, f'Serial {serial}')

    c.setFillColor(INK)
    c.setFont('Helvetica', 14)
    c.drawCentredString(cx, height - 170, 'This is to certify that')

    name = _latin1(holder_name)
    size = 28
    while size > 12 and stringWidth(name, 'Helvetica-Bold', size) > width - 140:
        size -= 1
    c.setFont('Helvetica-Bold', size)
    c.drawCentredString(cx, height - 207, name)

    y = height - 232
    if holder_org:
        c.setFillColor(MUTED)
        c.setFont('Helvetica', 13)
        c.drawCentredString(cx, y, _latin1(holder_org)[:100])
        y -= 8
    c.setFillColor(INK)
    c.setFont('Helvetica', 13)
    y -= 22
    for line in simpleSplit(_latin1(statement), 'Helvetica', 13, width - 160)[:3]:
        c.drawCentredString(cx, y, line)
        y -= 18
    y -= 10
    c.setFillColor(MUTED)
    c.setFont('Helvetica', 11)
    c.drawCentredString(cx, y, f'Issued {issued}   |   Valid until {expires}   |   Key {key_id}')

    # QR code and printed verification code
    c.drawImage(ImageReader(io.BytesIO(qr_png_bytes(link))), cx - 59, 100, 118, 118)
    c.setFont('Helvetica', 8)
    c.drawCentredString(cx, 89, 'Scan to verify, or enter this code on the verify page:')
    c.setFont('Courier', 8.5)
    c.setFillColor(INK)
    c.drawCentredString(cx, 77, token)
    c.setFillColor(MUTED)
    c.setFont('Helvetica-Oblique', 8)
    c.drawCentredString(cx, 52, _latin1(footer))
    c.showPage()
    c.save()
    return buf.getvalue()
