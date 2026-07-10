# Terminus: SOC 2 Readiness and Control Mapping

**Document type:** Internal readiness and control mapping. This is NOT an attestation of SOC 2 compliance, a certification claim, or a substitute for an independent audit.

**Scope and limitations:** This document maps Terminus capabilities to the AICPA Trust Services Criteria (TSC) relevant to a SQL circuit-breaker sidecar. It covers only the controls Terminus itself provides at the data-access layer. A SOC 2 Type II opinion requires an independent CPA-firm auditor examining the entire service organization, including organizational, personnel, physical, and change-management controls that are entirely outside Terminus's scope. Nothing in this document constitutes a compliance claim. Terminus "helps satisfy" or "provides controls that support" certain criteria; the deploying organization and its auditor must evaluate whether those controls, combined with their own organizational controls, are sufficient for their assertion.

**Last updated:** 2026-06-23

---

## 1. How to Read This Document

Each section maps a Trust Services Criteria category to:

- **What Terminus provides:** the specific shipped capability and a pointer to its reference document.
- **What the deploying organization owns:** controls Terminus cannot provide and that the org must implement independently.
- **Readiness note:** a plain-language assessment of the current state and any gaps.

The TSC categories referenced are: CC1 (Control Environment), CC2 (Communication and Information), CC3 (Risk Assessment), CC4 (Monitoring Activities), CC5 (Control Activities), CC6 (Logical and Physical Access Controls), CC7 (System Operations), and C (Confidentiality). These are the real AICPA TSC series. Only categories where Terminus has a genuine, documentable role are treated in depth; categories that are entirely the organization's responsibility are listed in Section 3.

---

## 2. Trust Services Criteria Mapping

### CC6: Logical and Physical Access Controls

This is the category where Terminus provides the strongest, most directly mapped controls.

#### CC6.1 and CC6.3: Logical access is restricted to authorized users and authenticated identities

**Terminus provides:**

- **Default-deny policy engine.** Every SQL query is denied unless it matches an explicit allow rule. The whitelist decides which tables are reachable at all; policy rules then govern what operations are permitted. A missing rule fails safe to deny. Reference: `docs/capabilities/policy-and-whitelists.md`.
- **Schema and column whitelisting.** `schema_whitelist.yaml` is a default-deny allow-list of tables. Tables may additionally carry a column-level allow-list, restricting which fields may be read or written. Wildcard column selectors on restricted tables are denied. Fail-closed on ambiguous column attribution in joins. Reference: `SECURITY.md`, `docs/capabilities/policy-and-whitelists.md`.
- **JWT-based agent identity.** Agents authenticate with an HS256 JSON Web Token (`Authorization: Bearer`). The trusted agent ID is derived from the verified `sub` claim; self-asserted headers are ignored once a valid token is present. Algorithm is pinned to HS256; `alg=none` and algorithm-confusion tokens are rejected. Reference: `docs/capabilities/agent-identity.md`, `SECURITY.md`.
- **Registry-gated agent allow-list.** A verified `sub` claim must also match a registered, active entry in `agents.yaml`. An unknown or disabled `sub` is rejected even with a cryptographically valid signature. This is the revocation mechanism. Reference: `docs/capabilities/agent-identity.md`.
- **Auth enforcement mode.** `TERMINUS_REQUIRE_AUTH=true` disables the self-asserted fallback entirely, requiring a valid JWT for every request. An invalid or expired token always returns 401 regardless of this flag. Reference: `docs/configuration.md`, `SECURITY.md`.

**What the organization owns:**

- Management of the `TERMINUS_JWT_SECRET` (>= 32 bytes, injected via a secret manager, never committed to source). The default dev placeholder is publicly known; leaving it in production makes all per-agent controls spoofable.
- Lifecycle processes for issuing and revoking agent tokens (out-of-band via the operator CLI; Terminus never mints tokens at runtime).
- Physical and network access controls to the host running Terminus and to the backing database.
- Identity governance for human operators who manage `agents.yaml` and policy files.
- Encryption in transit (TLS) between agents and the Terminus sidecar, and between Terminus and the database.

**Readiness note:** Strong. Default-deny is enforced at the API boundary. JWT identity is shipped and documentable. The primary operational risk is misconfiguration: leaving `TERMINUS_REQUIRE_AUTH=false` (the default, for migration convenience) allows the self-asserted legacy path. Production deployments should set `REQUIRE_AUTH=true` and confirm `terminus_auth_events_total{result="legacy"}` is zero. See `docs/operations.md` for the alert pattern.

---

#### CC6.2: Prior to issuing credentials, new users are registered and authorized

**Terminus provides:**

- **Registry-gated issuance.** The `python -m terminus.auth issue` CLI refuses to mint a token for an agent ID that does not exist in `agents.yaml`. Tokens can only be issued to pre-registered agents. Reference: `docs/capabilities/agent-identity.md`.
- **Revocation without secret rotation.** Setting `status: disabled` in `agents.yaml` (and letting the hot-reload apply it, or restarting) immediately blocks that agent's token without rotating the shared secret or invalidating other agents' tokens. Reference: `docs/capabilities/agent-identity.md`.

**What the organization owns:**

- The approval workflow for adding new agents to `agents.yaml` (who may authorize, what review is required, how the change is tracked).
- Separation of duty between the person deploying Terminus and the person authorizing new agent registrations.
- Periodic recertification of the agent registry (review for stale or no-longer-needed agents).

**Readiness note:** Partial. The technical gate is present (registry-gated issuance, revocation by flag). The organizational lifecycle controls (approval, periodic review) must be defined and documented by the deploying organization.

---

#### CC6.6: Logical access security measures restrict access to information assets

**Terminus provides:**

- **Per-agent policy scoping.** Policy rules support `agent_ids` match fields (with glob support), so different agents can be granted different operations on different tables. A `reporting_cron` agent and an `analytics_agent` can have strictly different allow sets. Reference: `docs/capabilities/policy-and-whitelists.md`.
- **Destructive operation blocking.** The example policy (and the recommended baseline) explicitly denies DROP, TRUNCATE, ALTER, CREATE, and DELETE. The policy engine enforces these as deny rules with `reason_code=policy_rule`. Reference: `docs/capabilities/policy-and-whitelists.md`.
- **SQL injection and smuggling defense.** The parser performs deep AST inspection using `sqlglot` to detect comment-based obfuscation, hidden subqueries and set operations (UNION, INTERSECT), and injection functions (benchmark(), sleep(), hex literals, char()). A query that cannot be safely parsed is denied outright. Reference: `SECURITY.md`.
- **Risk scoring and thresholds.** A `max_destructive_risk_score` limit can be set per policy rule, denying queries that exceed a computed risk score even if they otherwise match an allow rule. Reference: `docs/capabilities/policy-and-whitelists.md`.

**What the organization owns:**

- The content and intent of the policy files: which tables, agents, and operations are appropriate for the application. Terminus enforces what is configured; the organization decides what to configure.
- Review of policy changes (change management, peer review before deploying new policy files).
- Monitoring and response to `terminus_smuggling_attempts_total` spikes.

**Readiness note:** Strong for enforcement mechanics. Dependent on the organization defining appropriate policy content and change-management controls around `policy.yaml` and `schema_whitelist.yaml`.

---

#### CC6.8: Unauthorized or malicious software is prevented from being installed

**Terminus provides:**

- **Supply-chain integrity for signature bundles.** Threat-intelligence bundles pulled from a Hub are Ed25519-signed. The sidecar pins only the Hub's public key and verifies every bundle before applying it. A bundle with a bad signature is rejected; the last-known-good set is kept. Reference: `docs/capabilities/signature-flywheel.md`, `SECURITY.md`. Note: the receiving Hub is a future component (PDR Phase 4) and is not yet built; what ships today is the sidecar-side verify-before-trust verification and the opt-in, default-off outbound shipper. This maps the sidecar controls, which are ready for when a Hub exists; references to the Hub below are conditional on an organization choosing to operate one.
- **Privacy-preserving, fail-closed outbound telemetry.** When outbound telemetry is enabled (opt-in, default-off), the payload is a name-free structural projection re-verified by a privacy guard before queuing. A guard failure drops the payload rather than leaking data. Reference: `SECURITY.md`, `docs/capabilities/signature-flywheel.md`.

**What the organization owns:**

- Host-level controls: OS patching, container image scanning, runtime security for the host running Terminus.
- Supply-chain controls for the Terminus container image itself (image signing, registry access controls).
- Protection of the Hub's Ed25519 private key with HSM-grade controls (Terminus ships only the verification public key).

**Readiness note:** The bundle verification control is strong and documentable. Host and image supply-chain controls are entirely the organization's responsibility.

---

### CC7: System Operations

#### CC7.1: Infrastructure components are protected from environmental threats

**What the organization owns:** Entirely. Data center, host, network, container runtime controls are outside Terminus's scope.

---

#### CC7.2: System monitoring detects and responds to anomalies

**Terminus provides:**

- **Prometheus metrics.** Terminus exports a `/metrics` endpoint with labeled counters and histograms. Key series: `terminus_requests_total{action, reason, operation}` (every decision, with deny reason), `terminus_smuggling_attempts_total{reason}` (injection probes), `terminus_parser_latency_seconds` (p50/p95/p99), `terminus_active_agents` (distinct agents seen this process), `terminus_auth_events_total{result}` (JWT outcomes). Reference: `docs/operations.md`.
- **Grafana dashboard.** The bundled Docker stack includes a pre-wired Grafana dashboard charting request rate by decision/reason, parser latency, smuggling attempts, and active agents. Reference: `docs/operations.md`.
- **Structured audit log.** Every decision (allow and deny) is emitted as a structured JSON event on the `terminus.audit` log stream (`terminus_intercept_decision`), suitable for ingestion by a SIEM. Fields include agent ID, authentication status, operation, tables, risk score, reason code, and a SQL SHA-256 digest. Reference: `docs/capabilities/audit.md`.
- **Alert-worthy log events.** Documented events for Redis failure, bad config push, bundle verification failure, privacy guard trips, and signature outbound failures. Reference: `docs/operations.md` (key log events table).

**What the organization owns:**

- Ingesting the Prometheus metrics into the organization's monitoring platform and creating alert rules.
- Shipping the audit log stream to a SIEM or log aggregator for retention, search, and alerting.
- Incident response processes when monitoring detects anomalies.
- Setting alert thresholds and on-call rotation.

**Readiness note:** The telemetry infrastructure is built and documented. A Grafana dashboard ships with the Docker stack. The organization must connect these outputs to its own monitoring and incident response systems. Alert recommendations (rising `terminus_smuggling_attempts_total`, nonzero `legacy` auth, `config_reload_failed`) are documented in `docs/operations.md`.

---

#### CC7.3: Security incidents are identified and responded to

**Terminus provides:**

- **Tamper-evident HMAC-chained audit log.** Each audit event is signed with HMAC-SHA256, and the signature includes the prior event's signature, forming a verifiable chain. Removing, reordering, or altering any event breaks the chain from that point forward. The chain can be independently verified using `terminus.audit.verify.verify_audit_chain` without trusting the log's own assertions. Reference: `docs/capabilities/audit.md`, `SECURITY.md`.
- **No raw SQL in logs.** The audit log records a SHA-256 digest of the query, never the raw text, so the audit record is forensically useful without becoming a place where sensitive query content leaks. Reference: `SECURITY.md`, `docs/capabilities/audit.md`.
- **Reason codes for classification.** Every deny carries a `reason_code` (`schema_whitelist`, `column_whitelist`, `policy_rule`, `risk_threshold`, `signature_match`, `invalid_sql`, `multi_statement`, `nested_write`, `default`), enabling SIEM rules to classify and prioritize incidents by type. Reference: `docs/operations.md`.
- **Signature-based threat detection.** When signature matching is enabled, queries matching known-bad structural patterns are flagged (`observe` mode) or denied (`enforce` mode) with `reason_code=signature_match`, providing a basis for threat detection and alerting. Reference: `docs/capabilities/signature-flywheel.md`.

**What the organization owns:**

- A documented incident response plan and runbook.
- Secure, tamper-resistant log storage (shipping the audit stream off the host). Note: the HMAC chain is process-scoped and resets to a genesis signature on restart; durable cross-restart chain continuity is a documented planned enhancement (see `SECURITY.md`). Until it is implemented, the organization should treat each process lifecycle as a separate chain segment and document restart events.
- Legal and compliance obligations for breach notification.
- Forensic investigation processes using the audit evidence Terminus provides.

**Readiness note:** The forensic tooling is strong. The known gap is the process-scoped audit chain: chain continuity does not survive a restart. The organization must document restart events and store the per-session chain heads to maintain a full evidence record. This is a planned enhancement in Terminus, not an organizational policy gap, but the organization must account for it in its current attestation posture.

---

#### CC7.4: Security events are communicated to appropriate parties

**Terminus provides:**

- Structured, machine-readable deny events with reason codes, risk scores, and agent identity suitable for automated routing by a SIEM or alerting system.

**What the organization owns:**

- Escalation and notification workflows, on-call rotation, and communication plans for security events.

---

### CC4 and CC5: Monitoring Activities and Control Activities

#### CC4.1 and CC4.2: Monitoring and evaluation of controls

**Terminus provides:**

- **GitOps hot-reload with last-known-good.** Policy, schema whitelist, and agent registry are loaded from files. When `TERMINUS_CONFIG_RELOAD_INTERVAL` is set, changes are detected by SHA-256 hash, validated atomically, and swapped in without a restart. A malformed push is rejected and the prior configuration stays in force. The `terminus_config_reloads_total{result}` counter distinguishes `applied`, `unchanged`, and `failed`. Reference: `docs/capabilities/policy-and-whitelists.md`, `docs/configuration.md`.
- **Policy-as-code.** Governance files (`policy.yaml`, `schema_whitelist.yaml`, `agents.yaml`) are designed to live in version control, providing a reviewable, auditable change history of every access control decision. Reference: `docs/capabilities/policy-and-whitelists.md`.

**What the organization owns:**

- Storing governance files in a version-controlled repository with access controls and required code review before merging changes.
- Periodic review of policy rules for appropriateness (access recertification).
- Monitoring `terminus_config_reloads_total{result="failed"}` and responding to rejected config pushes.

---

#### CC5.2: Logical access controls are reviewed periodically

**Terminus provides:**

- `agents.yaml` as a versioned, machine-readable registry: the organization can query it to identify all registered agents and their status, supporting periodic access recertification.
- Auth metrics (`terminus_auth_events_total{result="legacy"}`) that surface agents still using the self-asserted path, flagging incomplete JWT migration.

**What the organization owns:**

- A defined recertification cadence and process for reviewing the agent registry and policy rules.
- Documentation of the review outcomes.

---

### CC1, CC2, CC3: Control Environment, Communication, Risk Assessment

These categories are primarily organizational. Terminus provides limited direct controls here, but its design supports these criteria in the following ways:

- **CC1 (Control Environment):** Policy-as-code governance files in version control support accountability and auditability of access control decisions. The deploying organization must establish the governance structure, management oversight, and ethical commitments that define the control environment.
- **CC2 (Communication and Information):** The audit log and Prometheus metrics provide machine-readable information about system behavior. The organization must establish processes to communicate this information to relevant stakeholders.
- **CC3 (Risk Assessment):** Terminus exports quantitative risk signals (risk scores, smuggling attempt counts, deny-reason breakdowns) that can inform an organization's threat and risk assessment processes. The organization must conduct and document the risk assessment itself.

---

### C: Confidentiality

#### C1.1 and C1.2: Confidential information is protected

**Terminus provides:**

- **No raw SQL in any output.** The query text is never logged, never returned in responses, and never included in outbound telemetry. Only a SHA-256 digest is recorded. This prevents audit logs from becoming a secondary exposure surface for sensitive query content. Reference: `SECURITY.md`, `docs/capabilities/audit.md`.
- **Privacy-preserving signature telemetry.** The structural signature used for threat intelligence carries only abstracted role classes and a deterministic hash, never table names, column names, or literal values. A single chokepoint function (`to_signature_facts`) performs the identifier abstraction; a fail-closed privacy guard re-validates every token before emission. Reference: `SECURITY.md`, `docs/capabilities/signature-flywheel.md`.
- **Connection URL scrubbing.** Redis connection URLs containing credentials are scrubbed before logging (`_safe_redis_target`), so credentials do not reach a log aggregator. Reference: `SECURITY.md`.
- **Column-level access restriction.** The column whitelist in `schema_whitelist.yaml` can restrict which fields an agent may reference, providing a technical control to prevent agents from accessing fields classified as confidential. This applies to writes as well as reads: an INSERT target column list is checked against the allowlist exactly like `UPDATE ... SET`, and an INSERT with no column list on a column-restricted table is denied outright, since it writes every column implicitly and cannot be proven within the allowed set without schema introspection. Enforcement depends on a faithful `sqlglot` parse, and Terminus does not read the database schema, so a column omitted from an explicit INSERT list is not itself schema-validated. Reference: `docs/capabilities/policy-and-whitelists.md`, `SECURITY.md`.

**What the organization owns:**

- Data classification: identifying which tables and columns contain confidential information and configuring the column whitelist accordingly.
- Encryption at rest for the database and for Terminus's audit log storage.
- Encryption in transit (TLS) for all Terminus API traffic.
- Data retention and deletion policies for the audit log.
- Agreements with subprocessors (if using the opt-in signature Hub telemetry, review the Hub's data handling).

**Readiness note:** The no-raw-SQL and privacy-preserving design is strong and verifiable from the codebase. The organization must configure the column whitelist to match its actual data classification and implement the encryption controls.

---

### Per-Agent Rate Limiting (Supporting CC6 and CC7)

**Terminus provides:**

- Per-agent rate limiting on `/intercept` via `fastapi-limiter` backed by Redis, keyed on the trusted (or self-asserted) agent ID, falling back to client IP. Default: 10 requests per minute, configurable via `TERMINUS_RATE_LIMIT_PER_MINUTE`. A rate-limited request returns HTTP 429. Reference: `SECURITY.md`, `docs/configuration.md`.
- **Fail-open behavior is documented and intended.** If Redis is unreachable, the limiter is skipped and SQL validation continues. The design intent is that rate limiting is a guardrail, not the core circuit breaker. `rate_limit_skipped` is logged as a warning. Reference: `SECURITY.md`, `docs/operations.md`.

**What the organization owns:**

- Sizing the rate limit for legitimate workloads and monitoring for 429 spikes.
- Deciding whether the fail-open behavior of rate limiting is acceptable in their threat model, and implementing compensating controls (Redis HA, network-level throttling) if it is not.

**Readiness note:** Rate limiting is operational. The auditor and the organization should note the fail-open design explicitly: a Redis outage degrades to no rate limiting, not to a denial of all traffic. This is a documented architectural choice, not a hidden gap.

---

## 3. What This Document Does Not Cover

The following control areas are entirely the deploying organization's responsibility. Terminus provides no direct controls in these areas and makes no claims about them.

- **Encryption at rest.** Terminus does not encrypt the database, the audit log files, or any persistent storage. This is the organization's and infrastructure team's responsibility.
- **Encryption in transit.** Terminus does not terminate TLS. TLS between agents and Terminus, and between Terminus and the database, must be configured at the infrastructure layer (load balancer, service mesh, etc.).
- **Network controls.** Firewall rules, network segmentation, and access to the host running Terminus are entirely outside Terminus's scope.
- **Physical security.** Data center, hardware, and physical access controls are the organization's responsibility.
- **Personnel controls.** Background checks, security training, acceptable-use policies, and separation of duties for human operators are organizational controls.
- **Change management (beyond policy-as-code).** Terminus supports policy-as-code as a pattern for governing its own configuration. A full change management program covering application development, deployment pipelines, and production change approvals requires organizational processes.
- **Vendor management.** If using the opt-in signature Hub telemetry, the organization must evaluate the Hub operator as a subprocessor.
- **Business continuity and disaster recovery.** High availability, backup, and recovery of the Terminus sidecar and its dependencies are infrastructure concerns.
- **Organizational-level risk assessment, policies, and procedures.** CC1, CC2, CC3, and A (Availability) criteria at the organizational level require management oversight, documented policies, and risk processes that Terminus cannot provide.

---

## 4. Production Configuration Checklist (Control Prerequisites)

For the Terminus-provided controls in Section 2 to be effective, the following must be set in every production deployment. These are documented in `docs/configuration.md` under "Must override in production."

| Variable | Requirement | Why it matters for controls |
|---|---|---|
| `TERMINUS_JWT_SECRET` | Random, >= 32 bytes, from a secret manager | Agent identity controls are spoofable with the default dev placeholder |
| `TERMINUS_AUDIT_HMAC_KEY` | Random, >= 32 bytes, stable across restarts | The audit chain is forgeable with the default; there is no error if unset |
| `TERMINUS_POLICY_PATH` | Your real policy file, not `examples/policy.yaml` | The example policy governs demo tables, not your tables |
| `TERMINUS_SCHEMA_WHITELIST_PATH` | Your real whitelist file | The example whitelist references demo tables |
| `TERMINUS_AGENT_REGISTRY_PATH` | Your real registry file | The example registry contains demo agents |
| `TERMINUS_REQUIRE_AUTH` | Set to `true` when all agents present JWTs | Leaves the self-asserted fallback path open until then |
| `TERMINUS_REDIS_URL` | Your Redis instance | Required for rate limiting to be active |

The two secrets are enforced at startup: when `TERMINUS_ENVIRONMENT` is not `development`, Terminus refuses to boot if `TERMINUS_JWT_SECRET` or `TERMINUS_AUDIT_HMAC_KEY` is left at its publicly-known shipped default (fail fast, not a silent degrade). The remaining rows (policy/whitelist/registry paths, Redis URL, `REQUIRE_AUTH`) are not enforced and still silently degrade the posture if left wrong, so the organization's deployment checklist and CI/CD pipeline should validate them before any production release.

---

## 5. Known Gaps and Planned Enhancements

These are limitations documented in Terminus source materials. They are not hidden; they are recorded here so an auditor can evaluate their significance and the organization can implement compensating controls.

- **Process-scoped audit chain.** The HMAC chain starts from a genesis signature on each process restart and does not span restarts. Durable cross-restart chain-head storage is a planned enhancement (`SECURITY.md`). Until implemented, each session is an independent chain segment. The organization should log and retain restart events and store the last `event_signature` before each restart to enable chain continuity documentation.
- **`max_queries_per_minute` in policy rules not enforced.** This field is parsed for forward compatibility but not enforced by the policy engine. Per-agent rate limiting is the Redis-backed `TERMINUS_RATE_LIMIT_PER_MINUTE` on the `/intercept` endpoint. Reference: `docs/capabilities/policy-and-whitelists.md`.
- **`TERMINUS_REQUIRE_AUTH` defaults to false.** The default is a migration aid. Until set to `true` and all agents present JWTs, the self-asserted identity path remains available. This is an operational readiness gap, not a design flaw, but it must be closed before a production attestation.
