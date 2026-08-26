import os
import base64
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage

from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger(__name__)

# --- Gmail SMTP config ---------------------------------------------------
# Use an App Password, NOT your regular Gmail password.
# Generate one at: https://myaccount.google.com/apppasswords
# (Requires 2FA to be enabled on your Google account.)
MAIL_FROM      = os.getenv("MAIL_FROM", "")
MAIL_PASSWORD  = os.getenv("MAIL_PASSWORD", "")
MAIL_FROM_NAME = os.getenv("MAIL_FROM_NAME", "Vista VMS")

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587  # TLS (STARTTLS)


def _smtp_send(msg: MIMEMultipart) -> bool:
    """Open a fresh SMTP connection, send msg, close it. Returns True on success."""
    if not MAIL_FROM or not MAIL_PASSWORD:
        logger.error("[Email] MAIL_FROM or MAIL_PASSWORD is not set in .env")
        return False
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(MAIL_FROM, MAIL_PASSWORD)
            server.sendmail(MAIL_FROM, msg["To"], msg.as_string())
        return True
    except smtplib.SMTPAuthenticationError:
        logger.error(
            "[Email] Gmail authentication failed. "
            "Make sure you're using an App Password, not your regular Gmail password. "
            "Generate one at https://myaccount.google.com/apppasswords"
        )
        return False
    except Exception as e:
        logger.error(f"[Email] Failed to send: {e}")
        return False


def _generate_qr_png(data: str) -> bytes:
    """Generate a QR code PNG. Falls back to a 1x1 placeholder if qrcode isn't installed."""
    try:
        import qrcode as qrc
        from io import BytesIO
        qr = qrc.QRCode(box_size=6, border=4)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except ImportError:
        return (
            b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
            b'\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00\x00'
            b'\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18'
            b'\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
        )


def _build_qr_html(visitor_name, host_name, visit_date, expected_time, purpose, qr_ref):
    return f"""\
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:system-ui,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:32px 0;">
    <tr><td align="center">
      <table width="480" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

        <tr><td style="background:#0F172A;padding:24px 32px;">
          <table width="100%" cellpadding="0" cellspacing="0"><tr>
            <td>
              <span style="font-size:20px;">&#128282;</span>
              <span style="color:#fff;font-size:16px;font-weight:700;margin-left:8px;">Vista VMS</span><br/>
              <span style="color:#94a3b8;font-size:12px;">Visitor Management System</span>
            </td>
            <td align="right">
              <span style="background:#16a34a;color:#fff;font-size:11px;font-weight:600;padding:4px 12px;border-radius:999px;">&#9989; Approved</span>
            </td>
          </tr></table>
        </td></tr>

        <tr><td style="padding:28px 32px;">
          <p style="margin:0 0 4px;font-size:14px;color:#64748b;">Hello,</p>
          <p style="margin:0 0 20px;font-size:22px;font-weight:700;color:#0f172a;">{visitor_name}</p>
          <p style="margin:0 0 20px;font-size:14px;color:#475569;line-height:1.6;">
            Your visit request has been <strong>approved</strong>. Please present this QR pass at the security desk upon arrival.
          </p>

          <table width="100%" cellpadding="0" cellspacing="0" style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;margin-bottom:24px;">
            <tr><td style="padding:20px;">
              {''.join(f'''
              <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:12px;">
                <tr>
                  <td style="font-size:12px;color:#94a3b8;width:120px;">{label}</td>
                  <td style="font-size:13px;font-weight:600;color:#0f172a;">{value}</td>
                </tr>
              </table>
              ''' for label, value in [
                ("Visiting",      host_name),
                ("Date",          visit_date),
                ("Time",          expected_time or "Flexible"),
                ("Purpose",       purpose),
                ("Reference No.", qr_ref),
              ])}
            </td></tr>
          </table>

          <table width="100%" cellpadding="0" cellspacing="0">
            <tr><td align="center" style="padding:20px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;">
              <img src="cid:qrcode" width="160" height="160" alt="QR Code" style="display:block;"/>
              <p style="margin:12px 0 0;font-size:12px;color:#64748b;">Scan this QR code at the security desk</p>
              <p style="margin:4px 0 0;font-family:monospace;font-size:13px;font-weight:700;color:#2563eb;">{qr_ref}</p>
            </td></tr>
          </table>

          <p style="margin:20px 0 0;font-size:12px;color:#94a3b8;line-height:1.6;">
            &#9888;&#65039; Please bring a valid government ID. The QR code is for one-time use only.<br/>
            If you can't scan the QR, show your reference number: <strong>{qr_ref}</strong>
          </p>
        </td></tr>

        <tr><td style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:16px 32px;text-align:center;">
          <p style="margin:0;font-size:11px;color:#94a3b8;">Vista VMS &middot; Argo HQ &middot; Paran&aacute;que City</p>
          <p style="margin:4px 0 0;font-size:11px;color:#94a3b8;">This is an automated message. Do not reply to this email.</p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>
"""


async def send_qr_pass_email(
    to_email: str,
    visitor_name: str,
    host_name: str,
    visit_date: str,
    expected_time: str,
    purpose: str,
    qr_ref: str,
) -> bool:
    """Send QR pass email via Gmail SMTP. Returns True on success."""
    qr_data = f"{qr_ref}|{visitor_name}|{visit_date}|{host_name}"
    qr_png  = _generate_qr_png(qr_data)

    msg = MIMEMultipart("related")
    msg["Subject"] = f"✅ Your Visit Pass — {visit_date} | Vista VMS"
    msg["From"]    = f"{MAIL_FROM_NAME} <{MAIL_FROM}>"
    msg["To"]      = to_email

    # HTML body in an "alternative" wrapper (plain-text fallback + HTML)
    alternative = MIMEMultipart("alternative")
    plain = (
        f"Hello {visitor_name},\n\n"
        f"Your visit has been approved.\n"
        f"Visiting: {host_name}\nDate: {visit_date}\nTime: {expected_time or 'Flexible'}\n"
        f"Purpose: {purpose}\nReference: {qr_ref}\n\n"
        f"Please present this reference number at the security desk.\n\nVista VMS"
    )
    alternative.attach(MIMEText(plain, "plain"))
    alternative.attach(MIMEText(
        _build_qr_html(visitor_name, host_name, visit_date, expected_time, purpose, qr_ref),
        "html",
    ))
    msg.attach(alternative)

    # Embed QR code image (inline, referenced as cid:qrcode in the HTML)
    img = MIMEImage(qr_png, _subtype="png")
    img.add_header("Content-ID", "<qrcode>")
    img.add_header("Content-Disposition", "inline", filename="qr_pass.png")
    msg.attach(img)

    return _smtp_send(msg)


# --- Status update email -------------------------------------------------

_STATUS_META = {
    "Rejected":    {"badge": "❌ Rejected",    "color": "#dc2626", "headline": "was not approved"},
    "Checked In":  {"badge": "🟢 Checked In",  "color": "#2563eb", "headline": "has been checked in"},
    "Checked Out": {"badge": "⬜ Checked Out", "color": "#64748b", "headline": "has been checked out"},
}


def _build_status_html(visitor_name, host_name, visit_date, status, extra_note=""):
    meta = _STATUS_META.get(status, {"badge": status, "color": "#64748b", "headline": f"is now '{status}'"})
    return f"""\
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"/></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:system-ui,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:32px 0;">
    <tr><td align="center">
      <table width="480" cellpadding="0" cellspacing="0" style="background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08);">

        <tr><td style="background:#0F172A;padding:24px 32px;">
          <table width="100%" cellpadding="0" cellspacing="0"><tr>
            <td>
              <span style="font-size:20px;">&#128282;</span>
              <span style="color:#fff;font-size:16px;font-weight:700;margin-left:8px;">Vista VMS</span><br/>
              <span style="color:#94a3b8;font-size:12px;">Visitor Management System</span>
            </td>
            <td align="right">
              <span style="background:{meta['color']};color:#fff;font-size:11px;font-weight:600;padding:4px 12px;border-radius:999px;">{meta['badge']}</span>
            </td>
          </tr></table>
        </td></tr>

        <tr><td style="padding:28px 32px;">
          <p style="margin:0 0 4px;font-size:14px;color:#64748b;">Hello,</p>
          <p style="margin:0 0 20px;font-size:22px;font-weight:700;color:#0f172a;">{visitor_name}</p>
          <p style="margin:0 0 20px;font-size:14px;color:#475569;line-height:1.6;">
            Your visit request to see <strong>{host_name}</strong> on <strong>{visit_date}</strong> {meta['headline']}.
            {extra_note}
          </p>
        </td></tr>

        <tr><td style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:16px 32px;text-align:center;">
          <p style="margin:0;font-size:11px;color:#94a3b8;">Vista VMS &middot; Argo HQ &middot; Paran&aacute;que City</p>
          <p style="margin:4px 0 0;font-size:11px;color:#94a3b8;">This is an automated message. Do not reply to this email.</p>
        </td></tr>

      </table>
    </td></tr>
  </table>
</body>
</html>
"""


async def send_status_update_email(
    to_email: str,
    visitor_name: str,
    host_name: str,
    visit_date: str,
    status: str,
    extra_note: str = "",
) -> bool:
    """Send a status-change notification (Rejected / Checked In / Checked Out) via Gmail SMTP."""
    prefix = {"Rejected": "❌", "Checked In": "🟢", "Checked Out": "⬜"}.get(status, "ℹ️")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"{prefix} Visit Update — {status} | Vista VMS"
    msg["From"]    = f"{MAIL_FROM_NAME} <{MAIL_FROM}>"
    msg["To"]      = to_email

    plain = (
        f"Hello {visitor_name},\n\n"
        f"Your visit to see {host_name} on {visit_date} {_STATUS_META.get(status, {}).get('headline', f'is now {status}')}.\n"
        f"{extra_note}\n\nVista VMS"
    )
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(_build_status_html(visitor_name, host_name, visit_date, status, extra_note), "html"))

    return _smtp_send(msg)
