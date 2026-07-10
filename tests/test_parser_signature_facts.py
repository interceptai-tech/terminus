"""Parser facts collected only when collect_signature_facts=True."""

from terminus.parser.sql_parser import SMUGGLING_PATTERNS, parse_sql


def test_facts_off_by_default() -> None:
    p = parse_sql("SELECT COUNT(*) FROM t WHERE a LIKE 'x%'")
    assert p.predicate_ops == []
    assert p.has_aggregate is False
    assert p.aggregate_only is False
    assert p.join_count == 0
    assert all(c.position == "other" for c in p.columns)


def test_aggregate_only_and_predicate_ops() -> None:
    p = parse_sql("SELECT COUNT(*) FROM t WHERE a LIKE 'x%'", collect_signature_facts=True)
    assert p.has_aggregate is True
    assert p.aggregate_only is True
    assert p.predicate_ops == ["LIKE"]


def test_mixed_projection_not_aggregate_only() -> None:
    p = parse_sql("SELECT COUNT(*), id FROM t WHERE id = 1", collect_signature_facts=True)
    assert p.has_aggregate is True
    assert p.aggregate_only is False
    assert p.predicate_ops == ["EQ"]


def test_column_positions() -> None:
    p = parse_sql("SELECT id FROM t WHERE name = 'x'", collect_signature_facts=True)
    by_name = {c.name: c.position for c in p.columns}
    assert by_name["id"] == "projection"
    assert by_name["name"] == "predicate"


def test_join_count() -> None:
    p = parse_sql(
        "SELECT a.id FROM a JOIN b ON a.id = b.id WHERE a.id = 1",
        collect_signature_facts=True,
    )
    assert p.join_count == 1


def test_smuggling_patterns_is_public() -> None:
    assert "sleep(" in SMUGGLING_PATTERNS


def test_aggregate_in_subquery_does_not_flip_outer() -> None:
    p = parse_sql(
        "SELECT id FROM t WHERE id IN (SELECT MAX(x) FROM s)",
        collect_signature_facts=True,
    )
    assert p.has_aggregate is False
    assert p.aggregate_only is False
