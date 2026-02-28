"""Unit tests for the infrared analyzer."""
import pathlib
import pytest
from lyseis.models import JSSource, SourceType, Severity
from lyseis.analyzer import infrared


FIXTURES = pathlib.Path(__file__).parent.parent / "fixtures"


def _source(content: str) -> JSSource:
    return JSSource(url="https://example.com/test.js", content=content, source_type=SourceType.EXTERNAL)


def test_internal_ip_detected():
    js = 'const backend = "http://10.0.0.5/api";'
    src = _source(js)
    findings = infrared.analyze(src, config=None)
    types = [f.type for f in findings]
    assert "INTERNAL_IP" in types


def test_internal_ip_severity_is_high():
    js = 'fetch("http://192.168.1.100/data");'
    src = _source(js)
    findings = infrared.analyze(src, config=None)
    ip_findings = [f for f in findings if f.type == "INTERNAL_IP"]
    assert all(f.severity == Severity.HIGH for f in ip_findings)


def test_s3_bucket_detected():
    content = (FIXTURES / "sample_graphql.js").read_text(encoding="utf-8")
    src = JSSource(url="https://example.com/app.js", content=content, source_type=SourceType.EXTERNAL)
    findings = infrared.analyze(src, config=None)
    types = [f.type for f in findings]
    assert "S3_BUCKET_URL" in types


def test_sourcemap_detected():
    content = (FIXTURES / "sample_graphql.js").read_text(encoding="utf-8")
    src = JSSource(url="https://example.com/app.js", content=content, source_type=SourceType.EXTERNAL)
    findings = infrared.analyze(src, config=None)
    types = [f.type for f in findings]
    assert "SOURCEMAP_REF" in types


def test_sourcemap_severity_is_high():
    js = "//# sourceMappingURL=main.chunk.js.map"
    src = _source(js)
    findings = infrared.analyze(src, config=None)
    sm_findings = [f for f in findings if f.type == "SOURCEMAP_REF"]
    assert all(f.severity == Severity.HIGH for f in sm_findings)


def test_staging_url_detected():
    js = 'const api = "https://staging.example.com/api";'
    src = _source(js)
    findings = infrared.analyze(src, config=None)
    types = [f.type for f in findings]
    assert "STAGING_URL" in types


def test_clean_file_no_infrared():
    content = (FIXTURES / "sample_clean.js").read_text(encoding="utf-8")
    src = JSSource(url="https://example.com/clean.js", content=content, source_type=SourceType.EXTERNAL)
    findings = infrared.analyze(src, config=None)
    assert findings == []


def test_172_range_is_internal():
    js = 'const host = "http://172.20.0.1/internal";'
    src = _source(js)
    findings = infrared.analyze(src, config=None)
    types = [f.type for f in findings]
    assert "INTERNAL_IP" in types
