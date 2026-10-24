"""Regression tests for the random first-run bootstrap credential lifecycle.

Release builds used to embed a shared ``dist/.env`` seed with the well-known
``baraqadmin`` password. These tests pin the replacement behaviour: generate
per-install credentials, expose them once through a 0600 handoff file, and
rotate any install that still carries the retired shared password.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from backend import config


class _FakeVault:
    """Minimal SecretVault stand-in; records every write."""

    def __init__(self, values: dict[str, str] | None = None):
        self.values = dict(values or {})
        self.stored: dict[str, str] = {}

    def get(self, name: str, default: str | None = None) -> str | None:
        return self.values.get(name, default)

    def set_many(self, values: dict[str, str]) -> None:
        self.values.update(values)
        self.stored.update(values)


@pytest.fixture(autouse=True)
def _isolate_first_run_env():
    """Remove bootstrap variables, then restore the rest of the suite's."""
    names = (
        "BARAQ_SKIP_SECRET_GEN",
        "BARAQ_ADMIN_PASSWORD",
        "BARAQ_API_KEYS",
        "BARAQ_TOKEN_SECRET",
        "BARAQ_ADMIN_USERNAME",
    )
    saved = {name: os.environ.get(name) for name in names}
    for name in names:
        os.environ.pop(name, None)
    yield
    for name, value in saved.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def _patch_config(monkeypatch, tmp_path, vault, password="generated-password"):
    credentials = tmp_path / "first_run_credentials.txt"
    monkeypatch.setattr(config, "_get_vault", lambda: vault)
    monkeypatch.setattr(config, "DEFAULT_ADMIN_PASSWORD", password)
    monkeypatch.setattr(config, "FIRST_RUN_CREDENTIALS_PATH", credentials)
    return credentials


def test_fresh_install_writes_handoff_file(monkeypatch, tmp_path):
    vault = _FakeVault()
    credentials = _patch_config(monkeypatch, tmp_path, vault)
    env_path = tmp_path / ".env"

    config._ensure_secure_secrets(env_path)

    assert len(vault.stored) == 3
    assert vault.stored["BARAQ_ADMIN_PASSWORD"] == "generated-password"
    assert set(json.loads(vault.stored["BARAQ_API_KEYS"]).values()) == {
        "admin",
        "analyst",
    }
    assert len(vault.stored["BARAQ_TOKEN_SECRET"]) == 64
    assert os.environ["BARAQ_ADMIN_PASSWORD"] == "generated-password"

    assert credentials.is_file()
    text = credentials.read_text(encoding="utf-8")
    assert "Password: generated-password" in text
    assert "Admin API key:" in text
    assert "Analyst API key:" in text
    if os.name != "nt":
        assert stat.S_IMODE(credentials.stat().st_mode) == 0o600


def test_retired_shared_password_is_rotated(monkeypatch, tmp_path):
    vault = _FakeVault(
        {
            "BARAQ_ADMIN_PASSWORD": config.INSECURE_BOOTSTRAP_PASSWORD,
            "BARAQ_API_KEYS": '{"old-admin-key": "admin"}',
            "BARAQ_TOKEN_SECRET": "old-token-secret",
        }
    )
    credentials = _patch_config(monkeypatch, tmp_path, vault)
    env_path = tmp_path / ".env"
    env_path.write_text(
        "BARAQ_ADMIN_PASSWORD=baraqadmin\n"
        'BARAQ_API_KEYS={"old-admin-key": "admin"}\n'
        "BARAQ_TOKEN_SECRET=old-token-secret\n"
        "BARAQ_KEEP_ME=1\n",
        encoding="utf-8",
    )

    config._ensure_secure_secrets(env_path)

    assert vault.stored["BARAQ_ADMIN_PASSWORD"] == "generated-password"
    assert vault.stored["BARAQ_API_KEYS"] != '{"old-admin-key": "admin"}'
    assert vault.stored["BARAQ_TOKEN_SECRET"] != "old-token-secret"
    assert os.environ["BARAQ_ADMIN_PASSWORD"] == "generated-password"

    # The stale bootstrap lines must not survive to be re-read next start.
    remaining = env_path.read_text(encoding="utf-8")
    assert "BARAQ_ADMIN_PASSWORD" not in remaining
    assert "BARAQ_API_KEYS" not in remaining
    assert "BARAQ_TOKEN_SECRET" not in remaining
    assert "BARAQ_KEEP_ME=1" in remaining

    text = credentials.read_text(encoding="utf-8")
    assert "Password: generated-password" in text
    assert config.INSECURE_BOOTSTRAP_PASSWORD not in text


def test_configured_credentials_are_not_rotated(monkeypatch, tmp_path):
    values = {
        "BARAQ_ADMIN_PASSWORD": "operator-chosen-password",
        "BARAQ_API_KEYS": '{"operator-admin-key": "admin"}',
        "BARAQ_TOKEN_SECRET": "operator-token-secret",
    }
    vault = _FakeVault(values)
    credentials = _patch_config(monkeypatch, tmp_path, vault)
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    config._ensure_secure_secrets(tmp_path / ".env")

    assert vault.stored == {}
    assert not credentials.exists()
    assert os.environ["BARAQ_ADMIN_PASSWORD"] == "operator-chosen-password"


def test_clear_first_run_credentials_removes_file(monkeypatch, tmp_path):
    credentials = tmp_path / "first_run_credentials.txt"
    credentials.write_text("Password: temporary\n", encoding="utf-8")
    monkeypatch.setattr(config, "FIRST_RUN_CREDENTIALS_PATH", credentials)

    config.clear_first_run_credentials()

    assert not credentials.exists()
    # A missing file is not an error (the normal steady-state case).
    config.clear_first_run_credentials()


def test_legacy_admin_password_hash_is_rotated(monkeypatch):
    from backend import main as app_main
    from backend.auth import hash_password, verify_password

    class _User:
        password_hash = hash_password(config.INSECURE_BOOTSTRAP_PASSWORD)
        must_change_password = False

    user = _User()
    monkeypatch.setattr(app_main, "ADMIN_PASSWORD", "rotated-password")

    assert app_main._rotate_legacy_bootstrap_password(user) is True
    assert user.must_change_password is True
    assert verify_password("rotated-password", user.password_hash)
    assert not verify_password(config.INSECURE_BOOTSTRAP_PASSWORD, user.password_hash)


def test_release_builds_do_not_embed_a_seed():
    root = Path(__file__).resolve().parents[1]
    for spec_name in ("baraq.spec", "baraq_onefile.spec"):
        spec = (root / spec_name).read_text(encoding="utf-8")
        assert '"seed"' not in spec
        assert 'dist" / ".env' not in spec

    script = (root / "scripts" / "build_release.ps1").read_text(encoding="utf-8")
    assert "New-SeedEnv" not in script
    assert "dist\\.env" not in script
