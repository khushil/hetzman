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


def test_bridge_subnet_outside_container_supernet_fails():
    """A standalone Incus host bootstrapped with its own addressing (e.g. the
    10.60.0.0/24 default of bootstrap-fsn1.sh) validates on every other rule but
    would silently get no NAT and no reverse DNS, because both are rendered
    against 10.100.0.0/16."""
    fleet = make_fleet()
    fleet["htz-hel1-dc12-bm-01"]["bridge_ip"] = "10.60.0.1"
    fleet["htz-hel1-dc12-bm-01"]["bridge_subnet"] = "10.60.0.0/24"
    errors = validate_registry(fleet)
    assert any("outside" in e and "10.100.0.0/16" in e for e in errors)


def test_vswitch_ip_outside_vswitch_subnet_fails():
    fleet = make_fleet()
    fleet["htz-hel1-dc12-bm-01"]["vswitch_ip"] = "10.9.9.9"
    errors = validate_registry(fleet)
    assert any("outside" in e and "10.0.0.0/24" in e for e in errors)


def test_supernet_check_accepts_the_real_fleet():
    """Guard against the new rule rejecting the live topology."""
    assert validate_registry(make_fleet()) == []


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
