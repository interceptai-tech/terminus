"""InterceptRequest.metadata shape bounds (GAPS L1, spec section 4).

Depth rule: the metadata object itself is depth 1; containers allowed at
depth 2; any dict/list at depth 3 is rejected; lists count like dicts.
Violations are 422 (transport-error class, like the body caps), never
audited denies.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from terminus.main import create_app

_ALLOWED_SQL = "SELECT id FROM public.users"
# examples/policy.yaml only allows this SELECT for an agent matching
# "analytics_agent_*" / "reporting_cron"; without it every request denies by
# default regardless of metadata, which would mask the bound under test.
_ALLOWED_AGENT_ID = "analytics_agent_42"


def _post(metadata: object) -> int:
    client = TestClient(create_app())
    return client.post(
        "/intercept",
        json={"sql": _ALLOWED_SQL, "agent_id": _ALLOWED_AGENT_ID, "metadata": metadata},
    ).status_code


def test_65_top_level_keys_rejected() -> None:
    assert _post({f"k{i}": i for i in range(65)}) == 422


def test_64_top_level_keys_accepted() -> None:
    assert _post({f"k{i}": i for i in range(64)}) == 200


def test_depth_3_dict_rejected() -> None:
    assert _post({"a": {"b": {"c": 1}}}) == 422


def test_depth_3_via_list_rejected() -> None:
    assert _post({"a": [[1]]}) == 422


def test_depth_2_dict_accepted() -> None:
    assert _post({"a": {"b": 1}, "c": [1, 2, 3]}) == 200


def test_empty_and_omitted_metadata_accepted() -> None:
    assert _post({}) == 200
    client = TestClient(create_app())
    assert (
        client.post(
            "/intercept", json={"sql": _ALLOWED_SQL, "agent_id": _ALLOWED_AGENT_ID}
        ).status_code
        == 200
    )
