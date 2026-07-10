# Terminus Architecture

This document provides a high-level overview of the Terminus system architecture. For the full product definition, see the Terminus Master PDR.

## High-Level Design

Terminus follows a **sidecar pattern**:

- **Data Plane (Spoke)**: Lightweight FastAPI application deployed close to the database (same VPC / Kubernetes cluster). Performs low-latency SQL interception, parsing, policy evaluation, and remediation.
- **Control Plane (Hub)**: Centralized management layer (future) for policy distribution, telemetry, and GitOps workflows. The sidecar can operate independently using last-known-good policies.

## Core Components (v0.1+)

1. **Interceptor** (`src/terminus/interceptor/`)
   - FastAPI application and request handling
   - Asynchronous event loop for high throughput

2. **Parser** (`src/terminus/parser/`)
   - `sqlglot`-based AST parsing and risk classification
   - Extracts operation, tables, referenced columns (best-effort attribution), presence of WHERE clauses, wildcard usage, and structured risk reasons.

3. **Policy Engine** (`src/terminus/policy/`)
   - Loads and evaluates `policy.yaml`
   - Supports priority ordering, agent scoping, conditions, and rate/risk limits

4. **Remediation** (`src/terminus/remediation/`)
   - Generates structured remediation suggestions
   - Returns `X-Terminus-Remediation` header + JSON body

5. **Audit** (`src/terminus/audit/`)
   - Structured, tamper-evident logging of every decision
   - JSON schema defined in the PDR

## Request Flow (Simplified)

Agent → Terminus Sidecar
↓
Parse SQL (sqlglot)
↓
Evaluate against active policies
↓
Decision: allow | deny | review
↓
(If deny) Generate remediation suggestion
↓
Return decision + optional remediation header to agent
↓
Write immutable audit event


## Key Design Goals

- **Latency**: < 1–2 ms p99 added latency on typical queries
- **Reliability**: Sidecar must not become a single point of failure (configurable fail-open/fail-closed)
- **Observability**: Prometheus metrics + structured audit logs
- **Security**: Default-deny, strong input validation, minimal attack surface

## Deployment

- Designed to run as a sidecar container or service mesh sidecar
- Communicates with databases via existing connection strings / proxies
- Future: Native support for common database proxies and service mesh integrations

For detailed component specs and data models, refer to the PDR sections on Software Design and Audit Event JSON Schema.

