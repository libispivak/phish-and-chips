"""The individual checks ("signals").

Each check looks at one thing, and returns a Signal (with a human-readable
explanation) or None. Weights live here, next to the logic they belong to.

deceptive=True marks evidence that someone is lying about who they are or
where a link goes. "Malicious" needs deception + a harmful call to action.
"""

import re
from dataclasses import dataclass
from typing import Optional

from .domains import normalize_host, org_domain, same_org
from .parser import ParsedEmail

STRONG, WEAK = "strong", "weak"


@dataclass
class Signal:
    """title/detail are written for everyday users (no jargon);
    technical is the precise evidence, for IT staff or anyone curious."""
    id: str
    title: str
    detail: str
    points: int
    strength: str
    deceptive: bool = False
    call_to_action: bool = False
    technical: str = ""


# ---------- A. Sender identity ----------

AUTH_DOMAIN = re.compile(
    r"(dkim|spf)=pass\b[^;]*?(?:header\.i=@?|header\.d=|smtp\.mailfrom=\"?[^@\s\"]*@)([a-z0-9.\-]+)",
    re.IGNORECASE,
)


def _passed_domains(email: ParsedEmail) -> set:
    return {normalize_host(m.group(2)) for m in AUTH_DOMAIN.finditer(email.auth_results.lower())}


DMARC_PASS = re.compile(r"dmarc=pass\b[^;]*?header\.from=([a-z0-9.\-]+)", re.IGNORECASE)


def sender_is_verified(email: ParsedEmail) -> bool:
    """True when the From domain itself passed authentication (DMARC-style alignment)."""
    auth = email.auth_results.lower()
    for match in DMARC_PASS.finditer(auth):
        if same_org(match.group(1), email.from_domain):
            return True
    return any(same_org(d, email.from_domain) for d in _passed_domains(email))


def check_auth_alignment(email: ParsedEmail) -> Optional[Signal]:
    if not email.auth_results:
        return Signal("A1", "We can't confirm who sent this",
                      "Gmail has no proof that this email really comes from the address shown.",
                      30, STRONG, deceptive=True,
                      technical="No Authentication-Results header from the receiving server (no SPF/DKIM/DMARC).")
    if sender_is_verified(email):
        return None
    passed_domains = _passed_domains(email)
    shown = ", ".join(sorted(passed_domains)) or "none"
    return Signal("A1", "The sender may be fake",
                  f"This email says it is from '{email.from_domain or 'unknown'}', but there is no proof "
                  f"it really is. Anyone can type any name and address as the sender.",
                  30, STRONG, deceptive=True,
                  technical=f"From domain '{email.from_domain}' is not aligned with any domain that passed "
                            f"SPF/DKIM ({shown}); no DMARC pass.")


EMAIL_IN_TEXT = re.compile(r"[a-z0-9._%+\-]+@([a-z0-9.\-]+\.[a-z]{2,})", re.IGNORECASE)


def check_display_name(email: ParsedEmail) -> Optional[Signal]:
    name = email.from_display_name
    if not name:
        return None
    for match in EMAIL_IN_TEXT.finditer(name):
        if not same_org(match.group(1), email.from_domain):
            return Signal("A2", "The sender's name is misleading",
                          f"The name you see is '{match.group(0)}', but the email actually came "
                          f"from a different address ('{email.from_domain}').",
                          20, STRONG, deceptive=True,
                          technical=f"Display name contains address '{match.group(0)}' whose domain differs "
                                    f"from the From domain '{email.from_domain}'.")
    compact = re.sub(r"[\s._\-]", "", name.lower())
    for local_part in email.recipient_local_parts:
        if compact and compact == re.sub(r"[._\-]", "", local_part):
            return Signal("A2", "The sender is pretending to be you",
                          f"The sender's name is your own name ('{name}'), but the email came "
                          f"from a stranger's address ('{email.from_domain}').",
                          20, STRONG, deceptive=True,
                          technical=f"Display name '{name}' matches the recipient's mailbox name; "
                                    f"From domain is '{email.from_domain}'.")
    return None


BRANDS = {
    "paypal": "paypal.com", "google": "google.com", "microsoft": "microsoft.com",
    "apple": "apple.com", "icloud": "icloud.com", "amazon": "amazon.com",
    "netflix": "netflix.com", "facebook": "facebook.com", "instagram": "instagram.com",
    "linkedin": "linkedin.com", "dhl": "dhl.com", "fedex": "fedex.com",
    "leumi": "leumi.co.il", "hapoalim": "bankhapoalim.co.il", "discount": "discountbank.co.il",
    "israelpost": "israelpost.co.il",
}
HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a"})


def _within_one_edit(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 1 or a == b:
        return False
    if len(a) == len(b):
        return sum(x != y for x, y in zip(a, b)) == 1
    short, long_ = (a, b) if len(a) < len(b) else (b, a)
    return any(long_[:i] + long_[i + 1:] == short for i in range(len(long_)))


def check_lookalike_domain(email: ParsedEmail) -> Optional[Signal]:
    org = org_domain(email.from_domain)
    if not org:
        return None
    name = org.split(".")[0]
    normalized = name.translate(HOMOGLYPHS).replace("rn", "m")
    verified = sender_is_verified(email)
    for brand, real_domain in BRANDS.items():
        if org == real_domain:
            return None
        # Big companies own many endings (amazon.dev, google.co.il, apple.co).
        # The exact brand name with another ending is fine when the sender is
        # verified; a misspelling (paypa1, rnicrosoft) is never fine.
        if name == brand and verified:
            return None
        looks_like = (
            normalized == brand
            or _within_one_edit(normalized, brand)
            or (brand in normalized and len(brand) >= 5 and re.search(r"secure|login|verify|account|support|service", normalized))
        )
        if looks_like:
            return Signal("A3", "The address imitates a well-known company",
                          f"'{org}' looks like '{real_domain}', but it is a different address. "
                          f"This is a common trick.",
                          30, STRONG, deceptive=True,
                          technical=f"From organizational domain '{org}' is a look-alike of '{real_domain}' "
                                    f"(edit distance / homoglyph / brand + keyword).")
    return None


GOOGLE_HELO = re.compile(r"from\s+([a-z0-9.\-]*google\.com)\s+\(([a-z0-9.\-]+)", re.IGNORECASE)


def check_forged_headers(email: ParsedEmail) -> Optional[Signal]:
    for name, value in email.headers.items():
        if "trusted sender" in str(value).lower():
            return Signal("A4", "The email lies about being trustworthy",
                          "It contains a hidden note claiming it comes from a 'trusted sender'. "
                          "Real emails don't do this. The sender wrote it to fool you and your filters.",
                          20, STRONG, deceptive=True,
                          technical=f"Header '{name}' contains a self-asserted 'Trusted Sender' claim.")
    for value in email.headers.get_all("Received") or []:
        match = GOOGLE_HELO.search(str(value))
        if match and not match.group(2).lower().rstrip(".").endswith("google.com"):
            return Signal("A4", "The email pretends to come from Google",
                          "It claims it was sent through Google's servers, but it wasn't.",
                          20, STRONG, deceptive=True,
                          technical=f"Received header: HELO '{match.group(1)}' but reverse DNS "
                                    f"'{match.group(2).rstrip('.')}'.")
    return None


# ---------- B. Links ----------

DOMAIN_LIKE = re.compile(r"(?:https?://)?((?:[a-z0-9\-]+\.)+[a-z]{2,})(?:[/\s]|$)", re.IGNORECASE)

# Email providers rewrite every link to go through their click counter first.
# For a verified sender this is normal; for an unverified one we still flag it.
CLICK_TRACKERS = (
    "awstrack.me", "sendgrid.net", "list-manage.com", "mandrillapp.com", "mlsend.com",
    "klclick.com", "klclick1.com", "klclick2.com", "flashy.app", "hubspotlinks.com",
    "sparkpostmail.com", "mailgun.org", "rs6.net", "ct.sendgrid.net", "click.convertkit-mail.com",
)


def _is_click_tracker(host: str) -> bool:
    return any(host == t or host.endswith("." + t) for t in CLICK_TRACKERS)


def check_link_text_mismatch(email: ParsedEmail) -> Optional[Signal]:
    verified = sender_is_verified(email)
    for link in email.links:
        match = DOMAIN_LIKE.match(link.text.strip())
        if not match or not link.host or same_org(match.group(1), link.host):
            continue
        if verified and _is_click_tracker(link.host):
            continue
        return Signal("B1", "A link is not what it seems",
                      f"A link shows '{match.group(1)}', but clicking it takes you somewhere else "
                      f"('{link.host}').",
                      30, STRONG, deceptive=True, call_to_action=True,
                      technical=f"Anchor text domain '{match.group(1)}' != href host '{link.host}'.")
    return None


PUBLIC_HOSTING = (
    "storage.googleapis.com", "firebasestorage.googleapis.com", "blob.core.windows.net",
    "s3.amazonaws.com", "r2.dev", "web.app", "firebaseapp.com", "pages.dev",
    "ipfs.io", "dweb.link", "glitch.me", "netlify.app", "vercel.app",
)


def check_public_hosting(email: ParsedEmail) -> Optional[Signal]:
    for link in email.links:
        host = link.host
        if not host or not any(host == h or host.endswith("." + h) for h in PUBLIC_HOSTING):
            continue
        if host.endswith("googleapis.com") and not link.path.lower().endswith((".html", ".htm")):
            continue  # images and files are fine; a web page there is not
        return Signal("B2", "A link leads to a suspicious page",
                      f"A link opens a page on a free file-sharing service ('{host}'). Real companies "
                      f"never ask you to log in or pay on pages like that.",
                      25, STRONG, deceptive=True, call_to_action=True,
                      technical=f"href to HTML page on public object storage / free hosting: {link.href[:120]}")
    return None


# ---------- C. Attachments ----------

EXECUTABLE_EXT = (
    ".exe", ".scr", ".com", ".bat", ".cmd", ".msi", ".js", ".jse", ".vbs", ".vbe",
    ".wsf", ".hta", ".ps1", ".jar", ".py", ".sh", ".lnk", ".iso", ".img",
    ".html", ".htm", ".svg",
)
MACRO_EXT = (".docm", ".xlsm", ".pptm", ".dotm", ".xlam")


def check_dangerous_attachments(email: ParsedEmail) -> Optional[Signal]:
    for att in email.attachments:
        for name in [att.filename] + att.archive_members:
            if name.lower().endswith(EXECUTABLE_EXT):
                where = f"inside '{att.filename}'" if name != att.filename else "attached"
                return Signal("C1", "An attachment could harm your computer",
                              f"'{name}' is a type of file that can run a program when you open it.",
                              30, STRONG, call_to_action=True,
                              technical=f"Executable/script extension: '{name}' ({where}).")
    return None


def check_macro_documents(email: ParsedEmail) -> Optional[Signal]:
    for att in email.attachments:
        for name in [att.filename] + att.archive_members:
            if name.lower().endswith(MACRO_EXT):
                return Signal("C2", "An attachment may hide a program",
                              f"'{name}' is an Office file that can run hidden programs when opened.",
                              25, STRONG, call_to_action=True,
                              technical=f"Macro-enabled Office format: '{name}'.")
    return None


def check_encrypted_archive(email: ParsedEmail) -> Optional[Signal]:
    for att in email.attachments:
        if att.archive_encrypted:
            return Signal("C3", "A locked attachment",
                          f"'{att.filename}' is locked with a password, so it can't be checked for viruses. "
                          f"Scammers do this to sneak past security.",
                          25, STRONG, call_to_action=True,
                          technical=f"Encrypted ZIP archive: '{att.filename}'.")
    return None


# ---------- D. Weak signals ----------

URGENCY = re.compile(
    r"action required|urgent|immediately|suspended|within 24 hours|final notice|"
    r"last hours|expires? today|account (?:will be )?(?:locked|closed)|"
    r"שעות אחרונות|דחוף|מיידי|יושעה|ייחסם|עד חצות|הזדמנות אחרונה",
    re.IGNORECASE,
)
CREDENTIAL_OR_PAYMENT = re.compile(
    r"update (?:your )?payment|payment method (?:has )?expired|update (?:your )?billing|"
    r"verify your (?:account|identity)|confirm your (?:password|account|identity)|"
    r"(?:re)?enter your password|wire transfer|buy (?:\w+ )?gift cards?|bank details|"
    r"עדכנ?(?:ו|י)? את (?:אמצעי|פרטי) (?:ה)?תשלום|פרטי (?:ה)?אשראי|אמת(?:ו|י)? את (?:ה)?חשבון|העברה בנקאית",
    re.IGNORECASE,
)


def check_urgency(email: ParsedEmail) -> Optional[Signal]:
    match = URGENCY.search(email.subject + " " + email.visible_text)
    if match:
        return Signal("D1", "It's rushing you",
                      f"It uses pressure words like '{match.group(0)}'. Scammers rush you so you "
                      f"don't stop to think. Shops do it too, so this alone is not a problem.",
                      5, WEAK, technical=f"Urgency phrase matched: '{match.group(0)}'.")
    return None


def check_credential_request(email: ParsedEmail) -> Optional[Signal]:
    match = CREDENTIAL_OR_PAYMENT.search(email.subject + " " + email.visible_text)
    if match:
        return Signal("D2", "It asks for payment or login details",
                      f"It mentions '{match.group(0)}' and wants you to act on it. Real companies rarely "
                      f"ask for payment or password details by email.",
                      10, WEAK, call_to_action=True,
                      technical=f"Credential/payment request phrase matched: '{match.group(0)}'.")
    return None


def check_hidden_text(email: ParsedEmail) -> Optional[Signal]:
    if email.hidden_element_count:
        return Signal("D3", "Part of the email is invisible",
                      "Some text is hidden from you. Newsletters do this a lot, "
                      "but scammers also use it to trick spam filters.",
                      5, WEAK, technical=f"{email.hidden_element_count} element(s) styled hidden "
                                         f"(display:none / opacity:0 / tiny font).")
    return None


def check_empty_body_with_attachment(email: ParsedEmail) -> Optional[Signal]:
    if email.attachments and len((email.subject + email.visible_text).strip()) < 20:
        return Signal("D4", "A file with no explanation",
                      "There's almost no text, only a file. If you weren't expecting it, "
                      "ask the sender before opening it.",
                      10, WEAK, technical="Fewer than 20 characters of subject + body text, with attachment(s).")
    return None


def check_reply_to(email: ParsedEmail) -> Optional[Signal]:
    if email.reply_to_domain and not same_org(email.reply_to_domain, email.from_domain):
        return Signal("D5", "Your reply would go to someone else",
                      f"If you press Reply, your answer goes to '{email.reply_to_domain}', "
                      f"not to the sender ('{email.from_domain}').",
                      10, WEAK, technical=f"Reply-To domain '{email.reply_to_domain}' differs from "
                                          f"From domain '{email.from_domain}'.")
    return None


def check_foreign_links(email: ParsedEmail) -> Optional[Signal]:
    foreign = sorted({link.host for link in email.links
                      if link.host and not same_org(link.host, email.from_domain)})
    if foreign:
        sample = ", ".join(foreign[:3]) + ("…" if len(foreign) > 3 else "")
        return Signal("D6", "Links go to other websites",
                      "The links lead to websites other than the sender's. This is usually harmless: "
                      "newsletters do it to count clicks.",
                      5, WEAK, technical=f"Link hosts not in the From organization: {sample}")
    return None


ALL_CHECKS = [
    check_auth_alignment, check_display_name, check_lookalike_domain, check_forged_headers,
    check_link_text_mismatch, check_public_hosting,
    check_dangerous_attachments, check_macro_documents, check_encrypted_archive,
    check_urgency, check_credential_request, check_hidden_text,
    check_empty_body_with_attachment, check_reply_to, check_foreign_links,
]
