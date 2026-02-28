"""Unit tests for the endpoints analyzer."""
import pathlib
import pytest
from lyseis.models import JSSource, SourceType, Severity
from lyseis.analyzer import endpoints


FIXTURES = pathlib.Path(__file__).parent.parent / "fixtures"


def _source(content: str) -> JSSource:
    return JSSource(url="https://example.com/test.js", content=content, source_type=SourceType.EXTERNAL)


def test_graphql_ref_detected():
    content = (FIXTURES / "sample_graphql.js").read_text(encoding="utf-8")
    src = JSSource(url="https://example.com/app.js", content=content, source_type=SourceType.EXTERNAL)
    findings = endpoints.analyze(src, config=None)
    types = [f.type for f in findings]
    assert "GRAPHQL_REFERENCE" in types


def test_websocket_detected():
    js = 'const ws = new WebSocket("wss://api.example.com/live");'
    src = _source(js)
    findings = endpoints.analyze(src, config=None)
    types = [f.type for f in findings]
    assert "WEBSOCKET_ENDPOINT" in types


def test_api_endpoint_detected():
    js = 'fetch("/api/v1/users", { method: "GET" });'
    src = _source(js)
    findings = endpoints.analyze(src, config=None)
    types = [f.type for f in findings]
    assert "API_ENDPOINT" in types or "VERSIONED_API_PATH" in types


def test_versioned_api_detected():
    js = 'const url = "/api/v2/payments/process";'
    src = _source(js)
    findings = endpoints.analyze(src, config=None)
    types = [f.type for f in findings]
    assert "VERSIONED_API_PATH" in types


def test_graphql_severity_is_high():
    js = "const q = gql`query { user { id } }`;"
    src = _source(js)
    findings = endpoints.analyze(src, config=None)
    gql_findings = [f for f in findings if f.type == "GRAPHQL_REFERENCE"]
    assert all(f.severity == Severity.HIGH for f in gql_findings)


def test_clean_file_no_endpoints():
    content = (FIXTURES / "sample_clean.js").read_text(encoding="utf-8")
    src = JSSource(url="https://example.com/clean.js", content=content, source_type=SourceType.EXTERNAL)
    findings = endpoints.analyze(src, config=None)
    assert findings == []
