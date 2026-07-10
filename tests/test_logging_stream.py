"""configure_logging(stream=...) must route structlog output to the given stream.

The MCP stdio transport owns stdout for protocol frames; the MCP entrypoint passes
sys.stderr so audit/log lines never corrupt the framing. Default (None) stays stdout
so the HTTP sidecar is byte-for-byte unchanged.
"""

from __future__ import annotations

import sys

import structlog

from terminus.audit.audit_logger import configure_logging


def test_default_logs_to_stdout(capsys):
    configure_logging()
    structlog.get_logger("t").warning("stream_probe_default")
    captured = capsys.readouterr()
    assert "stream_probe_default" in captured.out
    assert "stream_probe_default" not in captured.err


def test_stream_routes_to_stderr(capsys):
    configure_logging(stream=sys.stderr)
    structlog.get_logger("t2").warning("stream_probe_err")
    captured = capsys.readouterr()
    assert "stream_probe_err" in captured.err
    assert "stream_probe_err" not in captured.out
    configure_logging()  # restore default for other tests in the session
