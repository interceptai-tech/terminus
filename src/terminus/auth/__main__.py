"""Operator CLI for issuing agent JWTs. Run: python -m terminus.auth issue ...

This is an out-of-band operator tool. Terminus never mints tokens at runtime.
"""

from __future__ import annotations

import argparse
import contextlib
import sys
from datetime import timedelta

from terminus.auth.registry import get_registry
from terminus.auth.tokens import mint_token
from terminus.config.settings import get_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m terminus.auth", description="Terminus agent token tools"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    issue = sub.add_parser("issue", help="Mint a JWT for a registered agent")
    issue.add_argument("--agent", required=True, help="agent_id (must be registered and active)")
    group = issue.add_mutually_exclusive_group()
    group.add_argument(
        "--expires-days", type=int, default=30, help="token lifetime in days (default 30)"
    )
    group.add_argument("--no-expiry", action="store_true", help="mint a non-expiring token")
    args = parser.parse_args(argv)

    if args.command == "issue":
        # Operators capture this command's stdout (TOKEN=$(python -m
        # terminus.auth issue ...)), so stdout must carry exactly the token.
        # The CLI never calls configure_logging(), which leaves structlog on
        # its stdout-printing default, and the get_registry() call below
        # builds the governance snapshot, which can emit incidental log
        # events (e.g. policy_limit_not_enforced, GAPS L3). Redirect stdout
        # to stderr for all the work, then print the token AFTER the block.
        # A structlog.configure() call here would be wrong: it is a global,
        # process-wide switch that would leak into anything else running in
        # the same process (e.g. tests that call main() in-process).
        with contextlib.redirect_stdout(sys.stderr):
            if not get_registry().is_active(args.agent):
                print(
                    f"error: '{args.agent}' is not a registered, active agent; "
                    "add it to the registry first",
                    file=sys.stderr,
                )
                return 1
            if args.no_expiry:
                print(
                    "warning: non-expiring tokens are rejected wherever "
                    "TERMINUS_JWT_REQUIRE_EXP is enabled (the default in staging and "
                    "production); use --no-expiry for development only",
                    file=sys.stderr,
                )
            else:
                cap = get_settings().jwt_max_lifetime_seconds
                if cap > 0 and args.expires_days * 86_400 > cap:
                    print(
                        f"warning: --expires-days {args.expires_days} exceeds this "
                        f"environment's TERMINUS_JWT_MAX_LIFETIME_SECONDS ({cap}); "
                        "the token will be rejected here. The target environment's "
                        "cap may differ, so minting proceeds",
                        file=sys.stderr,
                    )
            expires_in = None if args.no_expiry else timedelta(days=args.expires_days)
            token = mint_token(args.agent, get_settings().jwt_secret, expires_in=expires_in)
        print(token)
        return 0

    return 2  # pragma: no cover - argparse requires a subcommand


if __name__ == "__main__":
    raise SystemExit(main())
