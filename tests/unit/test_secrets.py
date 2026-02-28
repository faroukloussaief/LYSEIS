"""Unit tests for the secrets analyzer."""
import pathlib
import pytest
from lyseis.models import JSSource, SourceType, Severity
from lyseis.analyzer import secrets


FIXTURES = pathlib.Path(__file__).parent.parent / "fixtures"


def _source(filename: str) -> JSSource:
    content = (FIXTURES / filename).read_text(encoding="utf-8")
    return JSSource(url=f"https://example.com/{filename}", content=content, source_type=SourceType.EXTERNAL)


def test_aws_access_key_detected():
    src = _source("sample_secrets.js")
    findings = secrets.analyze(src, config=None)
    types = [f.type for f in findings]
    assert "AWS_ACCESS_KEY" in types


def test_stripe_live_key_detected():
    src = _source("sample_secrets.js")
    findings = secrets.analyze(src, config=None)
    types = [f.type for f in findings]
    assert "STRIPE_LIVE_KEY" in types


def test_github_token_detected():
    src = _source("sample_secrets.js")
    findings = secrets.analyze(src, config=None)
    types = [f.type for f in findings]
    assert "GITHUB_TOKEN" in types


def test_jwt_detected():
    src = _source("sample_secrets.js")
    findings = secrets.analyze(src, config=None)
    types = [f.type for f in findings]
    assert "JWT_TOKEN" in types


def test_hardcoded_credential_detected():
    src = _source("sample_secrets.js")
    findings = secrets.analyze(src, config=None)
    types = [f.type for f in findings]
    assert "HARDCODED_CREDENTIAL" in types


def test_clean_file_no_secrets():
    src = _source("sample_clean.js")
    findings = secrets.analyze(src, config=None)
    assert findings == []


def test_finding_has_line_number():
    src = _source("sample_secrets.js")
    findings = secrets.analyze(src, config=None)
    for f in findings:
        assert f.line_number is not None
        assert f.line_number > 0


def test_finding_has_context():
    src = _source("sample_secrets.js")
    findings = secrets.analyze(src, config=None)
    for f in findings:
        assert isinstance(f.context, str)


def test_critical_severity_for_aws():
    src = _source("sample_secrets.js")
    findings = secrets.analyze(src, config=None)
    aws_findings = [f for f in findings if f.type == "AWS_ACCESS_KEY"]
    assert any(f.severity == Severity.CRITICAL for f in aws_findings)
