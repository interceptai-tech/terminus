"""Fetch the third-party libinjection SQLi test corpus at a PINNED commit.

Downloads a curated subset of the ``data/sqli-*.txt`` files from the
client9/libinjection repository (BSD-3-Clause) into the gitignored
``bench/corpora/libinjection/`` cache, verifies each file's content against a
recorded sha256 (content at a pinned commit must never change; a mismatch means
tampering, a CDN/proxy problem, or upstream history was rewritten -- any of
which we fail loudly on rather than silently score against unverified data),
and writes ``bench/out/provenance.json`` recording source URL, commit, license,
and fetch timestamp.

Corpus scope: the full ``data/`` directory at the pinned commit contains three
auto-generated fuzz dumps (sqli-sqlmap.txt, sqli-sqlmap-20130419.txt,
sqli-forums.txt) that together account for ~82,700 of the ~85,800 total
payload lines -- near-duplicate sqlmap-generated variations and a scraped
forum-name dump. Including them would turn a CI-speed appendix into a
multi-minute run for negligible added pattern diversity. This fetch pins the
other 30 files (~3,100 payloads), which retain full category diversity
(boolean/time blind, arithmetic, phpids, spiderlabs advisories, wordpress,
mysql-implicit, github-issue regressions, etc). The exclusion is recorded in
provenance.json, not hidden.

The payloads themselves are NEVER vendored into git (bench/corpora/ is
gitignored); this script must be re-run (``make bench-fetch``) in any
environment that needs them, including CI.

If network access is unavailable, this script fails loudly with the manual
steps below rather than faking a corpus or skipping silently.
"""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

# The commit is pinned to the libinjection repo's master HEAD as verified at
# authoring time (2018-03-12; the `data/` corpus itself was last touched
# 2017-05-21 per its own commit history and has been static since).
SOURCE_REPO = "https://github.com/client9/libinjection"
PINNED_COMMIT = "e86ff4019a4343579cc307d96d79272d5efcd1be"
LICENSE = "BSD-3-Clause"
RAW_URL_TEMPLATE = (
    f"https://raw.githubusercontent.com/client9/libinjection/{PINNED_COMMIT}/data/{{filename}}"
)

_OUT_DIR = Path(__file__).resolve().parent / "corpora" / "libinjection"
_PROVENANCE_PATH = Path(__file__).resolve().parent / "out" / "provenance.json"

# filename -> expected sha256 of the raw file content at PINNED_COMMIT.
# Verified against the live raw.githubusercontent.com content at authoring time.
EXPECTED_SHA256: dict[str, str] = {
    "sqli-@ru_raz0-20160705.txt": "33a6defb364e2f717143d858e8112046f81c93762d110768503fe4c44f0522f1",
    "sqli-arithmetic_blind_sqli.txt": "f6ca3f7699889601a8dff669313e90b36bf671f7b2f7284d114dd559a4057cc3",
    "sqli-arithmetic_variations.txt": "7050f83ff198fad2ae02fca9bd8e2d9ddbe84bd1325eaa0aca9b3cd053653429",
    "sqli-arneswinnen.net-boolean.txt": "31524bb954570db4bf8f25d1fb0ac8d192539e4bfae37ba983c1e90577bf65c1",
    "sqli-arneswinnen.net-time.txt": "b2191007fbe98ddc034b7b043eaa991180417cbe73d462e0417210406fc1124a",
    "sqli-comparitiveprecomputation.txt": "eae6ffe59cc3214d7f1fcd905c5097b371d4801b4fc535df598c0a37f95bb788",
    "sqli-edb-17934.txt": "b5a2c7a56032cdd7bf3d7dffe7cb63a359bd2f9ad4ce6890fbad0417aa73707f",
    "sqli-fullqueries.txt": "ef5f7ac1f1658bb4e95a12718215f701ed438c0b5272f0f376d1f3d1aa10903f",
    "sqli-fuzz-ischi.txt": "9cf2119e45654bcf655ba2ffaf83cc73822d57ef18bb70146c39150d41419ff8",
    "sqli-github-110.txt": "a641d0cd70fb68ae369c00d7841352b8f74bdd15a52ee86b2bcec93e709e41bf",
    "sqli-github-114.txt": "68af244ea73f93d471f60adcb28b78549651278209129e6f330256f9deefc407",
    "sqli-github-123.txt": "9b0d04edf67e36971103bef750cbf230460f24c8a03eef591e70726da359d71d",
    "sqli-github-125.txt": "65325177f34a0aa6312d5c6d8899556d1178553f2b164094803344022f33cd0b",
    "sqli-github-modsec-782.txt": "a77464a6fefccac4ae4d3dcac2a2f603cfd8fc0f5b393ffcb8396fc64331d064",
    "sqli-hackers.txt": "8afe0fb1a7c5d874180031e7c59eed3642ea988f9382fec6a4a1dfd6068b9c3f",
    "sqli-ibm.txt": "8622bf83e643f1779314d1e902231f29998cff9f9e8240a2746edec152fcb86d",
    "sqli-insert_attacks.txt": "adb5bc9865dc210ee43edcfc9cd8301eeb07413a0ad399f3b76341de6aafc402",
    "sqli-isc_sans.txt": "590797d8ccfff7da6c2cc083330ec2f8e4fce92cf5c414e3653f7d2817792874",
    "sqli-left.txt": "e1253347ee5a4932f4bc1883a266461da84e1fd339abb99d188b51aec618db0c",
    "sqli-misc.txt": "ccab0d90b213f8eac2203d0db9530d1e61907511aef4dde08771d9c77bf16680",
    "sqli-mysql-implicit.txt": "f0e04e7d61f6a6b215917212801c927396fab192d4e7c074d705b95334bee8c1",
    "sqli-phpids.txt": "902486592e15c06e25708df6b0cbd6c3e313cedb4769a8d5653b83a0bb5d87db",
    "sqli-rsalgado-bhusa2013.txt": "aa612f63c736e3cdffa413279d05c22c4a951dd874a75e195b245ee3ea3705a0",
    "sqli-spiderlabs-201107.txt": "1ced78af9e9227e28f6acc982de3be3e863bdf5953c68ba89d04a720651c9bae",
    "sqli-spiderlabs-201112.txt": "13f460c67bd8029b144438e228fd314288444f7972617ae4eb3fa3e88c76ed10",
    "sqli-spiderlabs-201205.txt": "8652dc2065a4a42850542983936e5e88f893ecda35f169f583e0af437de96680",
    "sqli-sqlmap-20160724.txt": "4e6cc620ccf6f1aeaa58609e035d41902a707b9ec69e2ba14e04b5e5960aab3c",
    "sqli-sqlmap_examples.txt": "698beafc667c3e3e91a98827aa49921a3a07212009b68ebc559bd7b80378ce6a",
    "sqli-themole.txt": "1da0c717aecd23bc409c7bd6925c5dd1e27bb73b046102c034f844257fc37d86",
    "sqli-wordpress_rbarnett.txt": "cf4ff7aba6a0191f50cc12c4d5911b7daa58a64b774b5b5b1a610254a6810f95",
}

# Auto-generated fuzz dumps deliberately excluded; see module docstring.
EXCLUDED_FILES: dict[str, str] = {
    "sqli-sqlmap.txt": "31,877 lines; sqlmap's own auto-generated regression payloads.",
    "sqli-sqlmap-20130419.txt": "36,765 lines; sqlmap's own auto-generated regression payloads.",
    "sqli-forums.txt": "14,023 lines; scraped forum-thread name/text dump.",
}

_MANUAL_STEPS = """
bench/fetch.py could not reach raw.githubusercontent.com to download the
libinjection corpus. This environment likely has no outbound network access.

Manual steps (run from a machine with network access, then copy the result
into this checkout at bench/corpora/libinjection/):

  mkdir -p bench/corpora/libinjection
  for f in {filenames}; do
    curl -fsSL "https://raw.githubusercontent.com/client9/libinjection/{commit}/data/$f" \\
      -o "bench/corpora/libinjection/$f"
  done

Then re-run `make bench-corpus` (or `python -m bench.run_corpus`) in this
checkout. bench/corpora/ is gitignored -- do not commit the downloaded files.
""".strip()


def _fail_loud(reason: str) -> int:
    print(f"bench/fetch.py: FAILED - {reason}", file=sys.stderr)
    print(file=sys.stderr)
    print(
        _MANUAL_STEPS.format(filenames=" ".join(EXPECTED_SHA256), commit=PINNED_COMMIT),
        file=sys.stderr,
    )
    return 1


def fetch_one(client: httpx.Client, filename: str) -> bytes:
    url = RAW_URL_TEMPLATE.format(filename=filename)
    response = client.get(url, timeout=30.0)
    response.raise_for_status()
    return response.content


def main() -> int:
    _OUT_DIR.mkdir(parents=True, exist_ok=True)
    fetched: list[dict[str, object]] = []

    try:
        with httpx.Client() as client:
            for filename, expected_sha in sorted(EXPECTED_SHA256.items()):
                content = fetch_one(client, filename)
                actual_sha = hashlib.sha256(content).hexdigest()
                if actual_sha != expected_sha:
                    return _fail_loud(
                        f"checksum mismatch for {filename}: expected {expected_sha}, "
                        f"got {actual_sha}. Content at a pinned commit should never "
                        "change; this may indicate tampering or a proxy rewriting "
                        "the response."
                    )
                (_OUT_DIR / filename).write_bytes(content)
                line_count = sum(
                    1
                    for line in content.decode("utf-8", errors="replace").splitlines()
                    if line.strip() and not line.startswith("#")
                )
                fetched.append(
                    {"filename": filename, "sha256": actual_sha, "payload_lines": line_count}
                )
                print(f"  fetched {filename} ({line_count} payloads)")
    except httpx.HTTPError as exc:
        return _fail_loud(f"{exc.__class__.__name__}: {exc}")

    provenance = {
        "source_url": SOURCE_REPO,
        "commit": PINNED_COMMIT,
        "license": LICENSE,
        "fetch_timestamp_utc": datetime.now(UTC).isoformat(),
        "note": (
            "Payloads are NOT vendored into git (bench/corpora/ is gitignored). "
            "Re-run `make bench-fetch` to repopulate. Checksums above are verified "
            "against the pinned commit's raw file content on every fetch."
        ),
        "files": fetched,
        "excluded_files": EXCLUDED_FILES,
    }
    _PROVENANCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _PROVENANCE_PATH.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    print(f"  wrote {_PROVENANCE_PATH}")
    print(f"  wrote {len(fetched)} files to {_OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
