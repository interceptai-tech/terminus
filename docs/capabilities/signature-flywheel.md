# The Signature Intelligence Flywheel

How Terminus turns the queries it sees into shared, privacy-preserving threat
intelligence, and how to operate it. This is the cohesive picture; the
per-variable knobs are in [docs/configuration.md](../configuration.md), the
operational signals in [docs/operations.md](../operations.md), and the full
design rationale in the specs linked at the bottom.

## The idea

The hard part of governing agent SQL is not the obvious `DROP TABLE`, it is the
plausible query that passes naive checks but violates intent, and the catalog of
those techniques grows adversarially. No single deployment sees enough of them.
The flywheel solves that: Terminus sits at the agent-to-data boundary across many
deployments, extracts a **privacy-preserving structural signature** of each
dangerous query (its shape and technique, never its data), and shares those
signatures so that a technique seen at one deployment immunizes the others.

The signature is the unit that makes this safe. It contains no table names, no
column names, and no literal values, only abstracted role classes and a
deterministic hash. That property holds at every stage below.

## The four stages

```
   (1) COLLECT            (2) MATCH               (3) DISTRIBUTE        (4) CONTRIBUTE
   extract a signature -> recognize a known   -> keep the known-bad -> ship local
   from each denied/      bad query and          set fresh from        signatures up
   suspicious query       escalate (or flag)     signed bundles        to the Hub (opt-in)
        |                      ^                        |                    |
        +----------------------+------------------------+--------------------+
                          all on the privacy-preserving signature
```

Stages 1 and 2 are local and zero-egress. Stage 3 pulls signed data in. Stage 4
(opt-in, default-off) is the only one that sends anything out. The Hub itself
(the shared "one brain") is not part of Terminus; the sidecar speaks its
contract.

## Stage 1: Collect (the extractor)

For every **denied or suspicious** query (denies, smuggling/hidden-subquery, or
an allow whose `risk_score` clears `TERMINUS_SIGNATURE_RISK_THRESHOLD`), Terminus
builds a `Signature` and emits it on the dedicated `terminus.signature` log
stream, separate from the audit log.

A signature records the query's **shape and technique** as a deterministic
`query_fingerprint` (a sha256 over the abstract structure) plus the technique
label, operation, and the structural role classes. The privacy boundary is a
single chokepoint: exactly one function (`to_signature_facts`) ever sees real
identifiers, and it converts them to role classes (`restricted`, `allowlisted`,
`unrestricted`, `aggregate`, `unattributed`, `unlisted`) and drops the names.
Everything downstream is name-free by construction, and a fail-closed guard
(`_assert_privacy`) re-checks every token against a fixed vocabulary before
anything is emitted: an unexpected token drops the signature rather than risk a
leak.

- **Turn it on:** `TERMINUS_SIGNATURES_ENABLED=true` (the default). Privacy-safe,
  and it is the data source the rest of the flywheel needs.
- **Tune sensitivity:** `TERMINUS_SIGNATURE_RISK_THRESHOLD` (lower captures more
  borderline allows).

## Stage 2: Match (the matcher and store)

With matching enabled, every query's fingerprint is checked against an in-memory
store of known-bad signatures. The action is **floor-and-tighten**: local policy
is the floor and is never weakened.

- **No match:** the local decision stands.
- **Observe-mode match:** annotate (`risk_reasons += signature_match`) and log,
  decision unchanged. This is the "would have blocked" signal.
- **Enforce-mode match** (with the global enforce posture on): escalate a local
  **allow** into a **deny** (`reason_code=signature_match`). A local deny is
  never downgraded.

That targets exactly the dangerous case: a query local policy *would have
allowed* but which matches a technique seen elsewhere. The store is O(1),
atomically swapped, and keeps its last-known-good set if an update fails.

- **Turn it on:** `TERMINUS_SIGNATURE_MATCHING_ENABLED=true` (off by default; off
  keeps Phase 1 behavior with no per-query fingerprint cost).
- **Roll out enforcement:** keep `TERMINUS_SIGNATURE_ENFORCE_ENABLED=false` to
  watch observe-mode telemetry first, then flip it on. Per-signature mode and the
  local overrides file refine this.

## Stage 3: Distribute (inbound signed updates)

The known-bad set is kept fresh by pulling **Ed25519-signed bundles** from a
configured source. The supply-chain rule is strict: the sidecar pins only the
Hub's **public** key and can verify but never forge. Verification happens before
the body is trusted; any failure (bad signature, tamper, parse, unsupported
format) is loud (ERROR) but safe, the store keeps last-known-good and the request
path is untouched.

Two version fields keep this honest. `fingerprint_version` is the algorithm
version; because a fingerprint is one-way, a bump is a hard cutover and records
of a non-matching version are skipped and counted
(`terminus_signature_version_skew_total`). `bundle_format_version` is the wire
format. A local overrides file lets a customer disable, re-mode, or add
signatures, and **local always wins** over bundle defaults, which is how you
suppress a false positive without waiting for a new bundle.

- **Point at a source:** `TERMINUS_SIGNATURE_BUNDLE_SOURCE` (an HTTPS URL, or a
  local file for air-gapped operation) plus
  `TERMINUS_SIGNATURE_BUNDLE_PUBLIC_KEY` (required to verify).
- **Stay fresh:** `TERMINUS_SIGNATURE_POLL_INTERVAL` (0 loads once at startup).
- **Local control:** `TERMINUS_SIGNATURE_OVERRIDES_PATH`.

## Stage 4: Contribute (outbound telemetry, opt-in)

To grow the shared corpus, a deployment can ship its locally-extracted signatures
up to the Hub. This is the only egress in the system, so it is **opt-in,
default-off, and fully inert** until configured. It rides the emitter as an extra
leg (a `CompositeEmitter` with per-leg isolation, so it can never break the local
log leg or the request). The outbound payload is a strict name-free projection of
an already-guarded signature, re-checked by the privacy guard before it is
queued, and shipped best-effort: a bounded buffer drops oldest on overflow, and a
background shipper batches, retries, then drops, never touching the request path.
A Hub outage degrades to "shared signatures, no contribution," nothing breaks.

- **Turn it on:** `TERMINUS_SIGNATURE_OUTBOUND_ENABLED=true` plus
  `TERMINUS_SIGNATURE_HUB_INGEST_URL` (and an optional
  `TERMINUS_SIGNATURE_HUB_TOKEN`). Off means zero egress.
- **Tune shipping:** the flush/batch/buffer trio (see configuration.md).

## The Hub (not built here)

The Hub is the receiving "one brain", ingest, storage, dedup, and cross-tenant
learning, and it is a separate project (PDR Phase 4), not a sidecar change. The
sidecar already speaks its contract: it verifies signed bundles coming in and
POSTs name-free payloads going out. Air-gapped deployments simply point the
inbound source at a local file and leave outbound off; they get shared immunity
without ever sending anything.

## Recommended rollout order

1. Leave extraction on (`SIGNATURES_ENABLED=true`); confirm `terminus_signature`
   log lines appear for denies.
2. Turn on matching (`SIGNATURE_MATCHING_ENABLED=true`) with enforcement off;
   watch `terminus_signature_matches_total{mode="observe"}`.
3. Point at a signed bundle source + public key; confirm `signature_bundle_applied`
   and a stable (or expected) `version_skew`.
4. Once you trust the corpus, enable enforcement
   (`SIGNATURE_ENFORCE_ENABLED=true`); watch for `signature_match` denies and use
   the overrides file for any false positive.
5. Optionally, enable outbound contribution to a Hub when one exists.

Operational signals for each step are in [docs/operations.md](../operations.md);
the exact variables in [docs/configuration.md](../configuration.md).

## Design references

- Phase 1 extractor: `docs/superpowers/specs/2026-06-22-signature-extractor-design.md`
- Phase 2A matching + inbound: `docs/superpowers/specs/2026-06-22-signature-intelligence-subsystem-design.md`
- Phase 2B outbound: `docs/superpowers/specs/2026-06-22-signature-intelligence-2b-outbound-design.md`
- Defensibility and the moat thesis: PDR Section 7.
