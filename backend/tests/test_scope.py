"""Guardrail unit tests — services/scope.validate_target."""

import pytest

from app.services.scope import validate_target


def test_private_ip_allowed():
    assert validate_target("192.168.56.10", "ip") == "allowed"
    assert validate_target("10.0.0.5", "ip") == "allowed"
    assert validate_target("172.16.3.4", "ip") == "allowed"


def test_loopback_and_link_local_allowed():
    assert validate_target("127.0.0.1", "ip") == "allowed"
    assert validate_target("169.254.1.1", "ip") == "allowed"


def test_public_ip_denied():
    assert validate_target("8.8.8.8", "ip") == "denied"


def test_public_ip_with_authorization_reference_allowed():
    assert (
        validate_target("8.8.8.8", "ip", authorization_reference="ENG-2026-0042")
        == "allowed"
    )


def test_public_ip_with_blank_authorization_reference_denied():
    assert validate_target("8.8.8.8", "ip", authorization_reference="   ") == "denied"


def test_private_cidr_allowed_and_public_cidr_denied():
    assert validate_target("192.168.0.0/16", "cidr") == "allowed"
    # 10.0.0.0/7 is not fully within 10.0.0.0/8 — must be denied.
    assert validate_target("10.0.0.0/7", "cidr") == "denied"
    assert validate_target("0.0.0.0/0", "cidr") == "denied"


def test_lab_hostname_allowed():
    assert validate_target("printer.office.lab", "hostname") == "allowed"
    assert validate_target("nas.local", "hostname") == "allowed"
    assert validate_target("staging.internal", "hostname") == "allowed"


def test_public_hostname_denied():
    assert validate_target("example.com", "hostname") == "denied"


def test_public_hostname_with_authorization_reference_allowed():
    assert (
        validate_target("example.com", "hostname", authorization_reference="PO-12345")
        == "allowed"
    )


def test_malformed_values_raise():
    with pytest.raises(ValueError):
        validate_target("not-an-ip", "ip")
    with pytest.raises(ValueError):
        validate_target("999.999.0.0/16", "cidr")
    with pytest.raises(ValueError):
        validate_target("whatever", "bogus-kind")
