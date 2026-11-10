"""Domain helpers.

We compare "organizational" domains (example.co.il, not mail.example.co.il),
because a company legitimately sends from sub-domains of its own domain.
This uses a short list of two-level suffixes instead of the full Public
Suffix List to stay dependency-free; it is good enough for the demo and is
listed as a known limitation in the README.
"""

from email.utils import parseaddr

TWO_LEVEL_SUFFIXES = {
    "co.il", "org.il", "ac.il", "gov.il", "net.il", "muni.il",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au",
    "co.jp", "ne.jp", "or.jp",
    "co.th", "in.th", "or.th",
    "com.vn", "net.vn",
    "web.id", "co.id", "or.id",
    "com.br", "com.cn", "com.sg", "com.tr", "com.mx", "com.ar",
    "co.in", "co.za", "co.nz", "co.kr",
}


def normalize_host(host: str) -> str:
    return (host or "").strip().strip(".").lower()


def org_domain(host: str) -> str:
    """mail.uniqlo.co.th -> uniqlo.co.th ; a.b.example.com -> example.com"""
    labels = [label for label in normalize_host(host).split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def address_domain(address: str) -> str:
    """'Name <user@mail.example.com>' -> 'mail.example.com'"""
    _, email_addr = parseaddr(address or "")
    if "@" not in email_addr:
        return ""
    return normalize_host(email_addr.rsplit("@", 1)[1])


def same_org(host_a: str, host_b: str) -> bool:
    a, b = org_domain(host_a), org_domain(host_b)
    return bool(a) and a == b
