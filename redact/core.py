"""Core redaction logic: pattern definitions and the redact_text() function.

No third-party dependencies - standard library only, so this runs anywhere
Python 3.8+ is available (including strictly-confined snaps).
"""

import re

# ---------------------------------------------------------------------------
# IPv4
# ---------------------------------------------------------------------------

RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:/\d{1,2})?\b'
)

# ---------------------------------------------------------------------------
# IPv6 - broad regex to find candidates, then a Python-side validator to
# filter out false positives like timestamps (10:00:01) which also match
# a "hex-groups-separated-by-colons" shape.
# ---------------------------------------------------------------------------

_H = '[0-9A-Fa-f]{1,4}'
RE_IPV6_CANDIDATE = re.compile(
    rf'\b(?:{_H})?(?::{{1,2}}(?:{_H})?){{2,7}}(?:/\d{{1,3}})?\b|::1\b'
)


def is_ipv6_like(candidate: str) -> bool:
    """Validate whether a regex candidate is a plausible IPv6 address,
    filtering out false positives such as timestamps (10:00:01)."""
    addr = candidate.split('/')[0]
    if addr.count(':') < 2:
        return False
    parts = addr.split(':')
    has_hex_letter = any(re.search(r'[A-Fa-f]', p) for p in parts)
    has_double_colon = '::' in addr
    if has_double_colon or has_hex_letter:
        return True
    # All-numeric, no "::": only accept 4+ groups (a full IPv6 address).
    # Timestamps (hh:mm:ss) have at most 3 groups.
    return len(parts) >= 4


# ---------------------------------------------------------------------------
# MAC address
# ---------------------------------------------------------------------------

RE_MAC = re.compile(r'\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b')

# ---------------------------------------------------------------------------
# Email addresses
# ---------------------------------------------------------------------------

RE_EMAIL = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')

# ---------------------------------------------------------------------------
# Generic hostnames / FQDNs: requires at least two labels ending in a
# recognized TLD/suffix, to avoid matching bare words.
# ---------------------------------------------------------------------------

RE_HOSTNAME = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'(?:internal|local|lan|corp|intranet|com|net|org|io|dev|cloud|xyz|ai|'
    r'delivery|co|edu|gov|info|biz)\b'
)

# ---------------------------------------------------------------------------
# Credentials / secrets - common known token/key patterns
# ---------------------------------------------------------------------------

CREDENTIAL_PATTERNS = [
    # AWS Access Key ID
    re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    # AWS Secret Key (heuristic: assignment + 40 base64-like chars)
    re.compile(r'(?i)(aws_secret_access_key\s*[:=]\s*)([A-Za-z0-9/+=]{40})'),
    # GitHub tokens
    re.compile(r'\bgh[pousr]_[A-Za-z0-9]{36,}\b'),
    # Slack tokens
    re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{10,}\b'),
    # JWT (header.payload.signature)
    re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'),
    # Bearer tokens in Authorization headers
    re.compile(r'(?i)(Bearer\s+)([A-Za-z0-9._-]{16,})'),
    # Generic PEM private key blocks
    re.compile(
        r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]+?'
        r'-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'
    ),
    # key=value / key: value where the key name suggests a secret
    re.compile(
        r'(?i)\b((?:api[_-]?key|apikey|secret|token|passwd|pwd|password|'
        r'access[_-]?key)\s*[:=]\s*)(["\']?)([^\s"\',;]{4,})(\2)'
    ),
]

REDACTION_TAGS = {
    'ip': '[REDACTED-IP]',
    'hostname': '[REDACTED-HOSTNAME]',
    'mac': '[REDACTED-MAC]',
    'email': '[REDACTED-EMAIL]',
    'credential': '[REDACTED-CREDENTIAL]',
}


def redact_text(text: str, extra_domains=None) -> str:
    """Redact IPs, hostnames, MACs, emails and credentials from `text`.

    extra_domains: optional list of client-specific domains to redact in
    addition to the generic hostname pattern (useful for custom TLDs or
    to explicitly scope which domains belong to a given engagement).
    """
    extra_domains = extra_domains or []

    # 1. Credentials first (before touching hostnames/IPs that could
    #    theoretically appear inside a token, though rare)
    for pat in CREDENTIAL_PATTERNS:
        if pat.groups == 0:
            text = pat.sub(REDACTION_TAGS['credential'], text)
        elif pat.groups == 2:
            text = pat.sub(lambda m: m.group(1) + REDACTION_TAGS['credential'], text)
        elif pat.groups == 4:
            text = pat.sub(
                lambda m: m.group(1) + m.group(2) + REDACTION_TAGS['credential'] + m.group(2),
                text,
            )

    # 2. Emails (before domains/hostnames, so we don't leave a residue like
    #    "user@[REDACTED-HOSTNAME]" when the domain also matches --domain
    #    or the generic hostname pattern)
    text = RE_EMAIL.sub(REDACTION_TAGS['email'], text)

    # 3. Explicit client domains
    for domain in extra_domains:
        pat = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)*' + re.escape(domain) + r'\b')
        text = pat.sub(REDACTION_TAGS['hostname'], text)

    # 4. MAC addresses
    text = RE_MAC.sub(REDACTION_TAGS['mac'], text)

    # 5. Generic hostnames/FQDNs
    text = RE_HOSTNAME.sub(REDACTION_TAGS['hostname'], text)

    # 6. IPv4 / IPv6
    text = RE_IPV4.sub(REDACTION_TAGS['ip'], text)
    text = RE_IPV6_CANDIDATE.sub(
        lambda m: REDACTION_TAGS['ip'] if is_ipv6_like(m.group(0)) else m.group(0),
        text,
    )

    return text
