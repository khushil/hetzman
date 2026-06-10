"""Unit tests for registry validation (the fail-closed gate for node-sync)."""
import copy

from hetzman.registry import validate_registry

from test_render import make_fleet


def test_valid_fleet_passes():
    assert validate_registry(make_fleet()) == []


def test_empty_registry_fails():
    assert validate_registry({}) == ["registry is empty"]


def test_duplicate_vswitch_ip_fails():
    fleet = make_fleet()
    fleet["htz-hel1-dc12-bm-01"]["vswitch_ip"] = "10.0.0.1"
    errors = validate_registry(fleet)
    assert any("duplicate vswitch_ip" in e for e in errors)


def test_overlapping_bridge_subnet_fails():
    fleet = make_fleet()
    fleet["htz-hel1-dc12-bm-01"]["bridge_subnet"] = "10.100.0.0/16"
    errors = validate_registry(fleet)
    assert any("overlaps" in e for e in errors)


def test_bridge_ip_outside_subnet_fails():
    fleet = make_fleet()
    fleet["htz-hel1-dc4-bm-01"]["bridge_ip"] = "10.100.9.1"
    errors = validate_registry(fleet)
    assert any("not in" in e for e in errors)


def test_missing_field_fails():
    fleet = make_fleet()
    del fleet["htz-hel1-dc3-bm-01"]["etcd_name"]
    errors = validate_registry(fleet)
    assert any("missing field 'etcd_name'" in e for e in errors)


def test_name_key_mismatch_fails():
    fleet = make_fleet()
    fleet["htz-hel1-dc3-bm-01"]["name"] = "wrong-name"
    errors = validate_registry(fleet)
    assert any("!= key" in e for e in errors)


def test_bad_schema_fails():
    fleet = make_fleet()
    fleet["htz-hel1-dc7-bm-01"]["schema"] = 99
    errors = validate_registry(fleet)
    assert any("unsupported schema" in e for e in errors)
