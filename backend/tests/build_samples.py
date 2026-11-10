"""Generates the synthetic test emails in tests/samples/.

All domains, names and addresses are invented (example.* / .test / reserved
names), so the samples are safe to publish. Real emails used for calibration
are NOT in the repository because they contain personal data.

Run:  python3 tests/build_samples.py
"""

import io
import zipfile
from email.message import EmailMessage
from pathlib import Path

OUT = Path(__file__).parent / "samples"

GOOGLE_RECEIVED = ("from mail-out.{d} (mail-out.{d}. [192.0.2.10]) by mx.google.com "
                   "with ESMTPS id test; Mon, 9 Nov 2026 10:00:00 -0800 (PST)")


def base(from_header, subject, auth, to="dana@example.org"):
    msg = EmailMessage()
    msg["Authentication-Results"] = auth
    msg["From"] = from_header
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = "Mon, 09 Nov 2026 18:00:00 +0000"
    return msg


def zip_bytes(files, encrypt_flag=False):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    raw = bytearray(buf.getvalue())
    if encrypt_flag:
        # Python can't write encrypted ZIPs; set the "encrypted" bit by hand in the
        # local header (offset 6) and central directory entry (offset 8). Single-file only.
        raw[6] |= 0x1
        central = raw.find(b"PK\x01\x02")
        raw[central + 8] |= 0x1
    return bytes(raw)


def legit_newsletter():
    msg = base('"Example Shop" <news@mail.shop.example>', "Last hours: 20% off everything ⏰",
               "mx.google.com; dkim=pass header.i=@mail.shop.example; spf=pass "
               "smtp.mailfrom=bounce@mail.shop.example; dmarc=pass (p=REJECT) header.from=shop.example")
    msg.set_content("Hi Dana, our sale ends at midnight.")
    msg.add_alternative(
        '<div style="display:none">Our biggest sale of the year</div>'
        '<p>Hi Dana, our sale ends at midnight.</p>'
        '<a href="https://click.tracker-esp.example/c/123">Shop now</a>'
        '<div style="border-top:1px solid #ddd;font-size:1px">&nbsp;</div>', subtype="html")
    return msg


def legit_receipt():
    msg = base('"Example Airlines" <receipts@example-airlines.example>', "Your booking receipt",
               "mx.google.com; dkim=pass header.i=@example-airlines.example; "
               "spf=pass smtp.mailfrom=receipts@example-airlines.example; "
               "dmarc=pass header.from=example-airlines.example")
    msg.set_content("Thank you for flying with us. Your booking reference is ABC123.")
    msg.add_attachment(b"%PDF-1.4 stub", maintype="application", subtype="pdf",
                       filename="receipt-ABC123.pdf")
    return msg


def phishing_lookalike():
    msg = base('"PayPal Service" <service@paypa1-secure.test>', "Action required: account suspended",
               "mx.google.com; spf=pass smtp.mailfrom=bounce@mailer.bulk-sender.test")
    msg["Reply-To"] = "help@collector.test"
    msg.set_content("Verify your account within 24 hours or it will be closed.")
    msg.add_alternative(
        "<p>We noticed unusual activity. Please verify your account within 24 hours.</p>"
        '<a href="http://paypa1-secure.test/login">www.paypal.com/security</a>', subtype="html")
    return msg


def phishing_public_hosting():
    msg = base('"Cloud Storage" <alerts@storage-alerts.test>', "Payment failed for your storage plan",
               "mx.google.com; dkim=pass header.i=@sender.unrelated.test; spf=pass "
               "smtp.mailfrom=x@sender.unrelated.test")
    msg["X-Original-Sender-Status"] = "Trusted Sender"
    msg["Received"] = ("from docs.google.com (relay.unrelated.test. [198.51.100.7]) by mx.google.com "
                       "with ESMTPS id test; Mon, 9 Nov 2026 10:00:00 -0800 (PST)")
    msg.add_alternative(
        "<p>Your payment method has expired. Please update your payment details.</p>"
        '<a href="https://storage.googleapis.com/some-bucket/update.html">Update payment method</a>'
        '<div style="opacity:0;font-size:1px">Madame, Monsieur, filler text for filters</div>',
        subtype="html")
    return msg


def friend_zip_with_script():
    msg = base('"Noa Friend" <noa.friend@gmail.com>', "",
               "mx.google.com; dkim=pass header.i=@gmail.com; spf=pass "
               "smtp.mailfrom=noa.friend@gmail.com; dmarc=pass header.from=gmail.com")
    msg.set_content("")
    msg.add_attachment(zip_bytes({"homework.py": b"print('hello')\n"}),
                       maintype="application", subtype="zip", filename="files.zip")
    return msg


def encrypted_zip_invoice():
    msg = base('"Accounts" <accounts@supplier.example>', "Invoice attached, password: 4417",
               "mx.google.com; dkim=pass header.i=@supplier.example; "
               "dmarc=pass header.from=supplier.example")
    msg.set_content("Please see the attached invoice. Password: 4417")
    msg.add_attachment(zip_bytes({"invoice.pdf": b"stub"}, encrypt_flag=True),
                       maintype="application", subtype="zip", filename="invoice.zip")
    return msg


def forged_auth_header():
    """The attacker adds their OWN 'Authentication-Results: mx.google.com; dmarc=pass'
    lower in the headers. Gmail's real header (on top) says the opposite."""
    msg = base('"Bank" <security@bank.example>', "Confirm your identity",
               "mx.google.com; spf=fail smtp.mailfrom=x@attacker.test; dmarc=fail header.from=bank.example")
    msg["Authentication-Results"] = "mx.google.com; dkim=pass header.i=@bank.example; dmarc=pass header.from=bank.example"
    msg.set_content("Please confirm your identity to keep using online banking.")
    return msg


SAMPLES = {
    "legit_newsletter.eml": legit_newsletter,
    "legit_receipt.eml": legit_receipt,
    "phishing_lookalike.eml": phishing_lookalike,
    "phishing_public_hosting.eml": phishing_public_hosting,
    "friend_zip_with_script.eml": friend_zip_with_script,
    "encrypted_zip_invoice.eml": encrypted_zip_invoice,
    "forged_auth_header.eml": forged_auth_header,
}

if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    for name, build in SAMPLES.items():
        (OUT / name).write_bytes(bytes(build()))
        print("wrote", OUT / name)
