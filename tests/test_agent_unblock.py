"""Agent-side unblock_ip support: validation and cross-agent rule cleanup."""

from __future__ import annotations

import pytest

from scripts.agent import UnsafeCommand, execute_command, validate_target


def test_validate_unblock_ip_accepts_valid_ip():
    assert validate_target("unblock_ip", "203.0.113.7") == "203.0.113.7"


def test_validate_unblock_ip_normalizes_ipv6():
    assert validate_target("unblock_ip", "::ffff:1.2.3.4") != ""


def test_validate_unblock_ip_rejects_garbage():
    with pytest.raises(UnsafeCommand):
        validate_target("unblock_ip", "not-an-ip")


def test_validate_unblock_ip_requires_target():
    with pytest.raises(UnsafeCommand):
        validate_target("unblock_ip", "")


def test_execute_unblock_ip_rejects_invalid_target(monkeypatch):
    called = []
    monkeypatch.setattr("scripts.agent._run", lambda cmd, env=None: called.append(cmd) or ("", 0))
    report = execute_command({"action": "unblock_ip", "target": "../evil"})
    assert report["status"] == "failed"
    assert called == []  # never reached netsh


def test_execute_unblock_ip_deletes_both_rule_families(monkeypatch):
    """The two agents name block rules differently; both must be cleaned up."""
    names_seen = []

    def fake_run(cmd, env=None):
        # cmd layout: [netsh, advfirewall, firewall, delete, rule, name=<name>]
        name_arg = cmd[-1]
        assert name_arg.startswith("name=")
        names_seen.append(name_arg[len("name="):])
        return ("Deleted 1 rule(s).", 0)

    monkeypatch.setattr("scripts.agent._run", fake_run)
    report = execute_command({"action": "unblock_ip", "target": "198.51.100.9"})
    assert report["status"] == "success"
    assert "4 rule(s) removed" in report["detail"]
    assert set(names_seen) == {
        "BARAQ Block 198.51.100.9 in",
        "BARAQ Block 198.51.100.9 out",
        "BARAQ-SOAR-IN-198-51-100-9",
        "BARAQ-SOAR-OUT-198-51-100-9",
    }


def test_execute_unblock_ip_fails_when_nothing_matched(monkeypatch):
    """netsh returns non-zero when no rule matches the exact name."""

    def fake_run(cmd, env=None):
        return ("No rules matched the specified criteria.", 1)

    monkeypatch.setattr("scripts.agent._run", fake_run)
    report = execute_command({"action": "unblock_ip", "target": "198.51.100.9"})
    assert report["status"] == "failed"
    assert "no BARAQ block rules found" in report["detail"]


def test_execute_unblock_ip_succeeds_on_partial_match(monkeypatch):
    """A block created by the other agent (SOAR naming) still gets undone."""
    soar_names = {"BARAQ-SOAR-IN-198-51-100-9", "BARAQ-SOAR-OUT-198-51-100-9"}

    def fake_run(cmd, env=None):
        name = cmd[-1][len("name="):]
        return ("Deleted 1 rule(s).", 0) if name in soar_names else ("No rules matched the specified criteria.", 1)

    monkeypatch.setattr("scripts.agent._run", fake_run)
    report = execute_command({"action": "unblock_ip", "target": "198.51.100.9"})
    assert report["status"] == "success"
    assert "2 rule(s) removed" in report["detail"]
