"""
lyseis.analyzer.secrets
~~~~~~~~~~~~~~~~~~~~~~~~
Detects hardcoded API keys, tokens, and credentials.

v0.1-r2 additions:
  - PEM private key (CRITICAL)
  - Firebase config block (HIGH)
  - Sentry DSN, Mapbox, NPM, Square, Discord, Telegram, Shopify, HuggingFace
  - Database/SMTP connection strings
  - Stripe restricted key (rk_live_)
  - GitHub OAuth/installation tokens (gho_, ghs_)
"""

from __future__ import annotations

from ..models import Finding, JSSource, Severity
from . import patterns


# ------------------------------------------------------------------ #
# Rule tuples: (finding_type, pattern, severity, capture_group_index)
# group=0  → full match
# group=N  → Nth capture group
# ------------------------------------------------------------------ #

_RULES: list[tuple[str, object, Severity, int]] = [
    # ---- Highest impact ----
    ("AWS_ACCESS_KEY",        patterns.AWS_ACCESS_KEY,       Severity.CRITICAL, 1),
    ("AWS_SECRET_KEY",        patterns.AWS_SECRET_KEY,       Severity.CRITICAL, 2),
    ("STRIPE_LIVE_KEY",       patterns.STRIPE_LIVE_KEY,      Severity.CRITICAL, 0),
    ("STRIPE_RESTRICTED_KEY", patterns.STRIPE_RESTRICTED_KEY,Severity.CRITICAL, 0),
    ("GITHUB_TOKEN",          patterns.GITHUB_TOKEN,         Severity.CRITICAL, 1),
    ("SENDGRID_KEY",          patterns.SENDGRID_KEY,         Severity.CRITICAL, 0),
    ("SHOPIFY_TOKEN",         patterns.SHOPIFY_TOKEN,        Severity.CRITICAL, 0),
    ("SQUARE_TOKEN",          patterns.SQUARE_TOKEN,         Severity.CRITICAL, 0),
    ("NPM_TOKEN",             patterns.NPM_TOKEN,            Severity.CRITICAL, 0),

    # ---- High impact ----
    ("STRIPE_TEST_KEY",       patterns.STRIPE_TEST_KEY,      Severity.HIGH, 0),
    ("GOOGLE_API_KEY",        patterns.GOOGLE_API_KEY,       Severity.HIGH, 0),
    ("JWT_TOKEN",             patterns.JWT_TOKEN,            Severity.HIGH, 0),
    ("SLACK_TOKEN",           patterns.SLACK_TOKEN,          Severity.HIGH, 0),
    ("TWILIO_KEY",            patterns.TWILIO_KEY,           Severity.HIGH, 0),
    ("MAILGUN_KEY",           patterns.MAILGUN_KEY,          Severity.HIGH, 0),
    ("DISCORD_TOKEN",         patterns.DISCORD_TOKEN,        Severity.HIGH, 0),
    ("TELEGRAM_TOKEN",        patterns.TELEGRAM_TOKEN,       Severity.HIGH, 0),
    ("MAPBOX_TOKEN",          patterns.MAPBOX_TOKEN,         Severity.HIGH, 0),
    ("HUGGINGFACE_TOKEN",     patterns.HUGGINGFACE_TOKEN,    Severity.HIGH, 0),
    ("SENTRY_DSN",            patterns.SENTRY_DSN,           Severity.HIGH, 0),
    ("DB_CONNECTION_STRING",  patterns.DB_CONNECTION_STRING, Severity.CRITICAL, 0),
    ("SMTP_CONNECTION_STRING",patterns.SMTP_CONNECTION,      Severity.CRITICAL, 0),
    ("TURN_CREDENTIAL",       patterns.TURN_CREDENTIAL,      Severity.HIGH, 1),
    ("GENERIC_API_KEY",       patterns.GENERIC_API_KEY,      Severity.HIGH, 2),
    ("HARDCODED_CREDENTIAL",  patterns.HARDCODED_CRED,       Severity.HIGH, 2),
]


def _get_context(lines: list[str], line_no: int, radius: int = 2) -> str:
    start = max(0, line_no - 1 - radius)
    end   = min(len(lines), line_no + radius)
    return "\n".join(lines[start:end])


def analyze(source: JSSource, config) -> list[Finding]:
    findings: list[Finding] = []
    lines = source.content.splitlines()

    # ---------------------------------------------------------------- #
    # Line-by-line rules (all _RULES above)
    # ---------------------------------------------------------------- #
    for rule_name, pattern, severity, group_idx in _RULES:
        for line_no, line in enumerate(lines, 1):
            for match in pattern.finditer(line):
                try:
                    value = match.group(group_idx) if group_idx > 0 else match.group(0)
                except IndexError:
                    value = match.group(0)

                if not value or len(value.strip()) < 4:
                    continue

                findings.append(
                    Finding(
                        type=rule_name,
                        value=value[:200].strip(),
                        severity=severity,
                        source_url=source.url,
                        source_type=source.source_type,
                        line_number=line_no,
                        context=_get_context(lines, line_no)[:400],
                    )
                )

    # ---------------------------------------------------------------- #
    # Full-content scan: PEM keys (span multiple lines)
    # ---------------------------------------------------------------- #
    for match in patterns.PEM_PRIVATE_KEY.finditer(source.content):
        line_no = source.content[: match.start()].count("\n") + 1
        findings.append(
            Finding(
                type="PEM_PRIVATE_KEY",
                value="[PEM PRIVATE KEY BLOCK DETECTED]",
                severity=Severity.CRITICAL,
                source_url=source.url,
                source_type=source.source_type,
                line_number=line_no,
                context=match.group(0)[:300],
            )
        )

    # ---------------------------------------------------------------- #
    # Full-content scan: Firebase config block
    # ---------------------------------------------------------------- #
    for match in patterns.FIREBASE_CONFIG.finditer(source.content):
        line_no = source.content[: match.start()].count("\n") + 1
        context = _get_context(lines, line_no, radius=4)
        findings.append(
            Finding(
                type="FIREBASE_CONFIG_BLOCK",
                value=match.group(0)[:350].strip(),
                severity=Severity.HIGH,
                source_url=source.url,
                source_type=source.source_type,
                line_number=line_no,
                context=context[:400],
            )
        )

    return findings
