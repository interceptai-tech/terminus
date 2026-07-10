"""Pydantic-based settings for Terminus using environment variables."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationInfo, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# The shipped, publicly-known development defaults. They are intentionally long
# enough (>= 32 bytes) to pass the length validator so local development works
# with zero setup, which means a production deploy that forgets to override them
# would otherwise run silently with a FORGEABLE audit chain (audit_hmac_key) and
# SPOOFABLE agent identity (jwt_secret). assert_production_secrets() rejects them
# outside development. Keep these as the single source of truth for both the
# field defaults and the guard so the two can never drift.
DEFAULT_AUDIT_HMAC_KEY = "super-secret-key-change-in-production-at-least-32-bytes"
DEFAULT_JWT_SECRET = "insecure-dev-jwt-secret-change-me-at-least-32-bytes"


class TerminusSettings(BaseSettings):
    """Main configuration for the Terminus sidecar.

    All settings are read from environment variables prefixed with TERMINUS_
    (e.g. TERMINUS_REDIS_URL, TERMINUS_LOG_LEVEL).

    .env file loading is DISABLED so Docker Compose environment variables
    always take precedence. For local development you can still export
    variables directly in your shell.

    Matching is case-INSENSITIVE so conventional UPPERCASE env vars work
    (e.g. TERMINUS_REDIS_URL -> redis_url). With case_sensitive=True the
    uppercase vars set by docker-compose were silently ignored and the
    defaults (including the audit HMAC signing key) were used instead.
    """

    model_config = SettingsConfigDict(
        env_prefix="TERMINUS_",
        env_file=None,  # Disabled so Docker env vars always win
        case_sensitive=False,
        extra="ignore",
    )

    environment: Literal["development", "staging", "production"] = "production"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    policy_path: Path = Path("examples/policy.yaml")
    schema_whitelist_path: Path = Path("examples/schema_whitelist.yaml")
    host: str = "0.0.0.0"
    port: int = 8000
    reload: bool = False

    # Docker-friendly default (overridden by TERMINUS_REDIS_URL in compose)
    redis_url: str = "redis://redis:6379"

    rate_limit_per_minute: int = 10
    audit_hmac_key: str = DEFAULT_AUDIT_HMAC_KEY

    # Agent identity (JWT/HS256). Override the secret in production (>= 32 bytes).
    jwt_secret: str = DEFAULT_JWT_SECRET
    require_auth: bool = False
    agent_registry_path: Path = Path("examples/agents.yaml")

    # Signature extractor (privacy-preserving threat telemetry).
    # When false, no signature work runs (parser fact collection is disabled too).
    signatures_enabled: bool = True
    # An ALLOWED query with risk_score >= this value is treated as suspicious and
    # emitted. Denies and smuggling/hidden-subquery queries are always emitted.
    signature_risk_threshold: float = 0.5

    # Signature Intelligence Subsystem (Phase 2A: local matching + inbound
    # updates). Matching is opt-in: off keeps Phase 1 behavior with no
    # per-query fingerprint.
    signature_matching_enabled: bool = False
    # When false, all matches are observe-only regardless of a signature's
    # mode. When true, enforce-mode signatures can escalate a local allow to
    # a deny.
    signature_enforce_enabled: bool = False
    # Inbound bundle source: an HTTPS URL (http is accepted for internal sources),
    # or a local file path. Empty means no updates.
    signature_bundle_source: str = ""
    # The Hub's Ed25519 public key: a filesystem path OR an inline PEM/base64
    # value.
    signature_bundle_public_key: str = ""
    # Seconds between bundle pulls. 0 = load once at startup, no polling.
    signature_poll_interval: int = 0
    # Path to the local overrides file (disable / mode override / local
    # signatures).
    signature_overrides_path: str = ""

    # Phase 2B: outbound telemetry (ship signatures to a Hub). All
    # default-inert: off means no buffer, no background task, no egress.
    signature_outbound_enabled: bool = False
    signature_hub_ingest_url: str = ""
    signature_hub_token: str = ""
    signature_outbound_flush_interval: int = 30
    signature_outbound_batch_max: int = 100
    signature_outbound_buffer_max: int = 1000

    # F9: per-agent velocity / sequence detection (blind-extraction oracle).
    # Opt-in behavioral guardrail, observe-by-default. A stateless-per-query engine
    # cannot see an oracle spread across many individually-allowed queries; this
    # counts extraction-shaped reads per agent and flags (optionally denies) a
    # threshold crossing. See docs/superpowers/specs/2026-07-06-f9-velocity-sequence-detection-design.md.
    velocity_enabled: bool = False
    velocity_enforce_enabled: bool = False
    velocity_window_seconds: int = Field(default=60, ge=1)
    velocity_threshold: int = Field(default=30, ge=1)
    velocity_max_tracked: int = Field(default=10000, ge=1)

    # GitOps hot-reload of the governance config (policy + whitelist + registry).
    # 0 = off (load once at startup, no poll task). > 0 = poll the files every N
    # seconds and atomically swap on change, keeping last-known-good on a bad config.
    config_reload_interval: int = 0

    # Allow-path smuggling defense. When true (default), a query that calls an
    # injection/time-based SQL function (pg_sleep, benchmark, ...) is denied on the
    # core path even if a policy rule would otherwise allow it. Set false to
    # observe-only (the signal is still surfaced in risk_reasons/metrics but never
    # changes the decision), for a one-deploy migration. Detection is AST-based, so
    # type names like varchar(255) are never affected.
    enforce_injection_block: bool = True

    # Maximum SQL length (characters) the parser will accept. A query over this is
    # denied (reason_code=oversize_sql) BEFORE parsing, so a single large or
    # pathological statement cannot block the event loop. Default 16 KiB is ~100x
    # the largest realistic agent query; raise it deliberately only after load
    # testing parser p99. The request body has a separate, coarser 128 KiB cap
    # (a 422), which must stay above this value so an over-cap query is an audited
    # deny rather than a bare validation error.
    max_sql_length: int = Field(default=16_384, gt=0)

    # F10c: the deployment database's SQL dialect. Drives identifier normalization
    # (both query identifiers and the whitelist/policy config) so matching follows
    # the dialect's case rules. Empty = generic (LOWERCASE), which is today's
    # Postgres behavior. Validated at boot by assert_known_dialect (fail-closed).
    sql_dialect: str = Field(default="")

    # Maximum request body size (bytes) accepted on any endpoint. A larger body is
    # rejected with 413 BEFORE it is read into memory / JSON-parsed, so an
    # oversized payload (huge sql, huge metadata) cannot burn memory in the request
    # path. Keep it above the 128 KiB sql field cap to leave room for the JSON
    # envelope and metadata. A hard network-layer limit still belongs at the
    # reverse proxy; this is the app-layer backstop.
    max_request_body_bytes: int = Field(default=262_144, gt=0)

    # Emit a signed audit checkpoint (the current chain head: boot_id, sequence,
    # head signature) every N decision events, plus one on graceful shutdown. A
    # downstream SIEM captures these out-of-band so truncation of the recent tail
    # becomes detectable: verification compares the live chain against the last
    # captured head. 0 disables periodic emission. This is amortized (one extra log
    # line per N requests), NOT a per-event fsync, to stay within the p99 budget.
    # The residual exposure window is the events since the last captured checkpoint.
    # None means "auto": 0 in development, 1000 in staging/production (GAPS M2);
    # never None after construction (_apply_environment_defaults).
    audit_checkpoint_interval: int | None = Field(default=None, ge=0)

    # MCP enforcement point (reference PEP for Postgres). Off by default: the MCP
    # server is a separate entrypoint (python -m terminus.mcp), so the HTTP sidecar
    # is byte-for-byte unchanged when these are unset.
    mcp_enabled: bool = False
    # The agent identity this MCP server instance serves, validated against the
    # registry at startup. One server per agent identity for the reference PEP;
    # per-session JWT via transport auth is a fast-follow.
    mcp_agent_id: str = ""
    # Postgres DSN the executor connects with. The ONLY place DB creds are set.
    mcp_postgres_dsn: str = ""
    # An allowed WRITE whose parsed risk_score is >= this triggers human-approval
    # break-glass. Policy/risk-driven (reuses the engine risk score), never a
    # hardcoded operation set. Default 0.8 catches DELETE (0.9/1.0) and no-WHERE
    # UPDATE (0.85); tune per deployment. Reads never require write-approval.
    mcp_approval_risk_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    # Seconds a pending high-risk write waits for approval before it expires as a
    # deny (fail-closed; never executes on timeout).
    mcp_approval_timeout_seconds: int = Field(default=300, gt=0)

    # Graduated autonomy (per-agent observe -> enforce promotion). Off by default:
    # when false, registry trust_level is ignored everywhere and behavior is
    # byte-for-byte the always-enforce pipeline.
    graduated_autonomy_enabled: bool = False

    # P1 hardening (GAPS M1/M5/H1). The three `| None` fields are environment-keyed:
    # None means "auto", filled by _apply_environment_defaults keyed on `environment`
    # (hardened in staging/production). An explicit TERMINUS_* env var always wins
    # because pydantic-settings populates the field before the validator runs.
    # After construction they are never None.
    #
    # Require and verify the JWT `exp` claim. Auto: True in staging/production.
    jwt_require_exp: bool | None = None
    # Reject tokens whose MINTED lifetime (exp - iat) exceeds this many seconds.
    # 0 = no cap. When > 0, `exp` and `iat` become required claims (fail-closed).
    jwt_max_lifetime_seconds: int = Field(default=0, ge=0)
    # Remove /docs, /redoc and /openapi.json from the app. Auto: True in
    # staging/production (GAPS M5: recon-surface reduction).
    disable_docs: bool | None = None
    # Operator attestation of the deployment's worker count; authoritative for the
    # multi-worker boot guard when set (GAPS H1). Unset = auto-detect.
    worker_count: int | None = Field(default=None, ge=1)
    # Boot despite a detected multi-worker launch, with a loud warning. The audit
    # chain, velocity trackers and signature store WILL silently fragment; the name
    # carries the risk on purpose.
    allow_unsafe_multi_worker: bool = False

    @field_validator("jwt_secret", "audit_hmac_key", mode="after")
    @classmethod
    def _require_strong_secret(cls, value: str, info: ValidationInfo) -> str:
        """Reject a secret shorter than 32 bytes; fail fast at startup.

        The audit HMAC chain and JWT identity are only as strong as these keys; a
        too-short secret silently makes both forgeable. The shipped defaults are
        well over 32 bytes, so only an explicitly weak override fails here.
        """
        length = len(value.encode("utf-8"))
        if length < 32:
            raise ValueError(
                f"{info.field_name} must be at least 32 bytes for cryptographic "
                f"safety (got {length}); set a strong secret via the environment."
            )
        return value

    @model_validator(mode="after")
    def _apply_environment_defaults(self) -> TerminusSettings:
        """Materialize the environment-keyed "auto" defaults (spec section 2).

        Runs after pydantic-settings has populated explicit env vars, so a None
        here can only mean "the operator did not set it". Hardened environments
        (staging/production) get the secure default; development keeps today's
        behavior byte-for-byte.
        """
        hardened = self.environment in ("staging", "production")
        if self.jwt_require_exp is None:
            self.jwt_require_exp = hardened
        if self.disable_docs is None:
            self.disable_docs = hardened
        if self.audit_checkpoint_interval is None:
            self.audit_checkpoint_interval = 1000 if hardened else 0
        return self


# Global singleton (lazy-loaded)
_settings: TerminusSettings | None = None


def get_settings() -> TerminusSettings:
    """Return (and cache) the application settings."""
    global _settings
    if _settings is None:
        _settings = TerminusSettings()
    return _settings


def assert_production_secrets(settings: TerminusSettings) -> None:
    """Refuse to run outside development with a publicly-known default secret.

    Length is not secrecy: the shipped defaults are >= 32 bytes, so the length
    validator accepts them. In any non-``development`` environment, a default
    ``audit_hmac_key`` makes the tamper-evident audit chain forgeable and a
    default ``jwt_secret`` makes every agent identity spoofable. Both are
    fail-open of a control PROJECT.md requires to fail closed, so we fail fast at
    startup rather than run insecure. This is called from the app lifespan; it is
    a no-op in development (where the defaults are the intended convenience).
    """
    if settings.environment == "development":
        return

    offenders: list[str] = []
    if settings.audit_hmac_key == DEFAULT_AUDIT_HMAC_KEY:
        offenders.append("audit_hmac_key")
    if settings.jwt_secret == DEFAULT_JWT_SECRET:
        offenders.append("jwt_secret")
    if not offenders:
        return

    joined = ", ".join(offenders)
    raise RuntimeError(
        f"refusing to start in environment={settings.environment!r} with the "
        f"publicly-known default value for: {joined}. Set a real secret via the "
        f"environment (TERMINUS_JWT_SECRET / TERMINUS_AUDIT_HMAC_KEY), or set "
        f"TERMINUS_ENVIRONMENT=development for local/demo use."
    )


def assert_known_dialect(settings: TerminusSettings) -> None:
    """Refuse to boot on an unknown TERMINUS_SQL_DIALECT (fail-closed).

    An empty value is the generic dialect and is always allowed. A typo must not
    silently fall back to lowercase normalization, so reject it at startup.

    ``Dialect.get_or_raise`` accepts anything sqlglot's dialect registry knows,
    including alias-only entries (e.g. "singlestore") that are not values of the
    ``Dialects`` enum. ``parse_sql`` gates on ``KNOWN_DIALECTS``, which IS built
    from that enum, so a dialect that boots here but is not in KNOWN_DIALECTS
    would make parse_sql return invalid_sql for every query -- a fail-closed
    self-inflicted denial of service. Require membership in the same known set
    parse_sql uses, so the two surfaces can never disagree.
    """
    if not settings.sql_dialect:
        return
    from sqlglot.dialects.dialect import Dialect

    from terminus.parser.sql_parser import KNOWN_DIALECTS

    try:
        Dialect.get_or_raise(settings.sql_dialect)
        if settings.sql_dialect.lower() not in KNOWN_DIALECTS:
            raise ValueError("alias-only dialect, not a KNOWN_DIALECTS member")
    except Exception as exc:
        raise ValueError(
            f"TERMINUS_SQL_DIALECT={settings.sql_dialect!r} is not a known SQL dialect"
        ) from exc
