from __future__ import annotations

from pathlib import Path

from pov.harness import main, run_in_process

_MINI = """
- id: sf_flag_probe_allow
  sql: "SELECT id FROM public.users WHERE id = 1"
  dialect: snowflake
  category: benign_read
  expected_decision: allow
"""


def test_run_in_process_accepts_corpus_path(tmp_path: Path) -> None:
    corpus = tmp_path / "mini.yaml"
    corpus.write_text(_MINI, encoding="utf-8")
    result = run_in_process(out_dir=tmp_path / "out", corpus_path=corpus)
    assert len(result.outcomes) == 1
    assert result.outcomes[0].id == "sf_flag_probe_allow"


def test_main_accepts_corpus_flag(tmp_path: Path) -> None:
    """Locks in the argparse --corpus wiring end-to-end: main() -> run_in_process(
    corpus_path=...). A single benign allow entry has no deny entries, so the
    self-correction rate denominator is empty and defaults to 1.0 -- the gate
    passes on this tiny corpus and main() returns 0 (PoV PASSED)."""
    corpus = tmp_path / "mini.yaml"
    corpus.write_text(_MINI, encoding="utf-8")
    exit_code = main(["--corpus", str(corpus), "--out", str(tmp_path / "out")])
    assert exit_code == 0
