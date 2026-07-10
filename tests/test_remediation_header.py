"""Remediation header control-character sanitization (GAPS M4, spec section 3).

The header value interpolates attacker-influenced identifiers; a bare CR is
the classic response-splitting primitive, and uvicorn/h11 turns it into a 500
on an otherwise-valid deny. Every C0 control byte and DEL must become a space
BEFORE truncation.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from terminus.remediation.remediation import _header_value

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


@pytest.mark.parametrize(
    "message",
    [
        "Column 'pass\rword' is not allowed",
        "Column 'pass\tword' is not allowed",
        "Column 'pass\x00word' is not allowed",
        "line one\nline two",
        "mixed \r\n\t\x0b\x7f soup",
    ],
)
def test_header_value_strips_all_control_chars(message: str) -> None:
    value = _header_value(message, ["fix \r it", "then\tretry"])
    assert not _CONTROL.search(value)
    assert value  # never scrubbed to empty for real input


def test_header_value_plain_text_unchanged() -> None:
    value = _header_value("Rewrite the query.", ["Use allowed columns."])
    assert value == "Rewrite the query. Use allowed columns."


def test_header_value_truncation_cap_unchanged() -> None:
    value = _header_value("x" * 600, [])
    assert len(value) == 500


def test_deny_with_cr_identifier_is_403_not_500() -> None:
    """End to end: a deny whose SQL embeds a CR in a quoted identifier must
    return a clean 403 with a single-line header, whichever deny path fires."""
    from terminus.main import create_app

    client = TestClient(create_app())
    response = client.post(
        "/intercept",
        json={"sql": 'SELECT "pass\rword" FROM public.users'},
    )
    assert response.status_code == 403
    header = response.headers.get("x-terminus-remediation", "")
    assert not _CONTROL.search(header)
