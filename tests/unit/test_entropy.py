"""Unit tests for the entropy analyzer."""
import pathlib
import pytest
from lyseis.models import JSSource, SourceType, Severity
from lyseis.analyzer import entropy


FIXTURES = pathlib.Path(__file__).parent.parent / "fixtures"


def _source(content: str) -> JSSource:
    return JSSource(url="https://example.com/test.js", content=content, source_type=SourceType.EXTERNAL)


def test_high_entropy_with_keyword_is_high_severity():
    js = 'const apiKey = "AAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBB1234567890abcdef";'
    src = _source(js)
    findings = entropy.analyze(src, config=None)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_high_entropy_without_keyword_is_info():
    # Long random-looking string with no credential keyword nearby
    js = 'const foo = "zXcVbNmQwErTyUiOpLkJhGfDsA1234567890zXcVbNmQ";'
    src = _source(js)
    findings = entropy.analyze(src, config=None)
    # If found, should be INFO (no keyword)
    for f in findings:
        assert f.severity == Severity.INFO


def test_short_strings_ignored():
    js = 'const x = "abc123";'
    src = _source(js)
    findings = entropy.analyze(src, config=None)
    assert findings == []


def test_low_entropy_ignored():
    # Low-entropy long string (all same char repeated)
    js = 'const s = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaa";'
    src = _source(js)
    findings = entropy.analyze(src, config=None)
    assert findings == []


def test_clean_file_no_entropy():
    content = (FIXTURES / "sample_clean.js").read_text(encoding="utf-8")
    src = JSSource(url="https://example.com/clean.js", content=content, source_type=SourceType.EXTERNAL)
    findings = entropy.analyze(src, config=None)
    assert findings == []


def test_shannon_entropy_known_values():
    assert round(entropy.shannon_entropy("aaaa"), 2) == 0.0
    assert entropy.shannon_entropy("abcdefghij0123456789") > 4.0
