import os
import base64
import logging

from dotenv import load_dotenv
import httpx

load_dotenv()

logger = logging.getLogger(__name__)

# --- EmailJS config ------------------------------------------------------
# Emails go out through EmailJS's own servers, so hosting providers that
# block outbound SMTP (e.g. Render) can't stop delivery. Everything that
# makes the email pretty still lives in the HTML builders below — EmailJS
# is only a transport: the dashboard template is Subject={{subject}},
# To Email={{to_email}}, Content={{html}}.
EMAILJS_SERVICE_ID    = os.getenv("EMAILJS_SERVICE_ID", "")
EMAILJS_TEMPLATE_QR   = os.getenv("EMAILJS_TEMPLATE_QR_ID", "")
EMAILJS_TEMPLATE_ALT  = os.getenv("EMAILJS_TEMPLATE_STATUS_ID", "")  # optional; falls back to QR template
EMAILJS_PUBLIC_KEY    = os.getenv("EMAILJS_PUBLIC_KEY", "")
EMAILJS_PRIVATE_KEY   = os.getenv("EMAILJS_PRIVATE_KEY", "")

EMAILJS_URL = "https://api.emailjs.com/api/v1.0/email/send"


async def _emailjs_send(to_email: str, subject: str, html: str, template_id: str = "") -> bool:
    """POST the rendered email to EmailJS REST API. Returns True on success."""
    template_id = template_id or EMAILJS_TEMPLATE_QR
    if not (to_email and html):
        logger.error("[Email] Missing recipient or body")
        return False
    if not (EMAILJS_SERVICE_ID and EMAILJS_PUBLIC_KEY and EMAILJS_PRIVATE_KEY and template_id):
        logger.error(
            "[Email] EmailJS not fully configured — set EMAILJS_SERVICE_ID, "
            "EMAILJS_PUBLIC_KEY, EMAILJS_PRIVATE_KEY and a TEMPLATE_*_ID in .env"
        )
        return False

    payload = {
        "service_id": EMAILJS_SERVICE_ID,
        "template_id": template_id,
        "user_id": EMAILJS_PUBLIC_KEY,
        "accessToken": EMAILJS_PRIVATE_KEY,
        "template_params": {
            "to_email": to_email,
            "subject": subject,
            "html": html,
        },
    }
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(EMAILJS_URL, json=payload)
        if resp.status_code == 200:
            return True
        logger.error(f"[Email] EmailJS send failed: {resp.status_code} {resp.text[:500]}")
        return False
    except Exception as e:
        logger.error(f"[Email] EmailJS request error: {e}")
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


def _build_qr_html(visitor_name, host_name, visit_date, expected_time, purpose, qr_ref, qr_img_src=""):
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
              <img src="{qr_img_src}" width="160" height="160" alt="QR Code" style="display:block;"/>
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
    """Send QR pass email via EmailJS (keeps the original HTML template). Returns True on success."""
    qr_data = f"{qr_ref}|{visitor_name}|{visit_date}|{host_name}"
    qr_png  = _generate_qr_png(qr_data)
    qr_img  = "data:image/png;base64," + base64.b64encode(qr_png).decode("ascii")

    html    = _build_qr_html(visitor_name, host_name, visit_date, expected_time, purpose, qr_ref, qr_img)
    subject = f"✅ Your Visit Pass — {visit_date} | Vista VMS"
    return await _emailjs_send(to_email, subject, html, EMAILJS_TEMPLATE_QR)


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
    """Send a status-change notification (Rejected / Checked In / Checked Out) via EmailJS.

    Reuses the QR template when no dedicated status template is configured —
    both templates are just {{subject}} + {{html}}, so this works either way.
    """
    prefix = {"Rejected": "❌", "Checked In": "🟢", "Checked Out": "⬜"}.get(status, "ℹ️")

    subject = f"{prefix} Visit Update — {status} | Vista VMS"
    html    = _build_status_html(visitor_name, host_name, visit_date, status, extra_note)
    template_id = EMAILJS_TEMPLATE_ALT or EMAILJS_TEMPLATE_QR
    return await _emailjs_send(to_email, subject, html, template_id)