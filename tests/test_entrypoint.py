import json

import pytest
from box import Box

import entrypoint


def test_get_grouped_domains_groups_vhosts_and_sans():
    cfg = Box(
        {
            "domains": {
                "api.example.org": {
                    "sans": ["www.example.org", "alt.example.org"],
                },
                "shop.test.io": {
                    "cert": "letsencrypt",
                    "sans": ["www.test.io", "www.other.net"],
                },
                "internal.example.org": {
                    "cert": "own",
                    "sans": ["ignored.example.org"],
                },
            }
        }
    )

    grouped = entrypoint.get_grouped_domains(cfg)

    assert grouped == {
        "example.org": [
            {"domain": "api.example.org", "type": "vhost"},
            {"domain": "www.example.org", "type": "san"},
            {"domain": "alt.example.org", "type": "san"},
        ],
        "test.io": [
            {"domain": "shop.test.io", "type": "vhost"},
            {"domain": "www.test.io", "type": "san"},
            {"domain": "www.other.net", "type": "san"},
        ],
    }


def test_get_grouped_domains_ignores_invalid_domains(capsys):
    cfg = Box(
        {
            "domains": {
                "api.example.org": {"sans": ["not-a-valid-domain"]},
            }
        }
    )

    grouped = entrypoint.get_grouped_domains(cfg)
    out = capsys.readouterr().out

    assert grouped == {"example.org": [{"domain": "api.example.org", "type": "vhost"}]}
    assert "not-a-valid-domain" in out


def test_apply_defaults_sets_missing_and_preserves_existing():
    cfg = Box({"server_tokens": "on"})
    applied = entrypoint.apply_defaults(cfg)

    assert applied.server_tokens == "on"
    for key, value in entrypoint.DEFAULTS.items():
        assert key in applied
        if key != "server_tokens":
            assert applied[key] == value


def test_compute_domain_hash_is_stable_for_san_order():
    a = Box({"sans": ["b.example.org", "a.example.org"], "cert": "letsencrypt"})
    b = Box({"sans": ["a.example.org", "b.example.org"], "cert": "letsencrypt"})

    assert entrypoint.compute_domain_hash("api.example.org", a) == entrypoint.compute_domain_hash(
        "api.example.org", b
    )


def test_store_and_get_domain_hash_round_trip(tmp_path):
    store_path = tmp_path / "domain_hashes.json"
    domain = Box({"sans": ["www.example.org"]})

    stored = entrypoint.store_domain_hash(str(store_path), "api.example.org", domain)
    loaded = entrypoint.get_domain_hash(str(store_path), "api.example.org")

    assert loaded == stored
    assert json.loads(store_path.read_text(encoding="utf-8"))["api.example.org"] == stored


def test_get_domain_hash_raises_if_store_is_not_a_json_object(tmp_path):
    store_path = tmp_path / "domain_hashes.json"
    store_path.write_text('["not-an-object"]', encoding="utf-8")

    with pytest.raises(TypeError, match="JSON object"):
        entrypoint.get_domain_hash(str(store_path), "api.example.org")


def test_create_dhparams_copies_bundled_file_when_create_is_false(monkeypatch):
    calls = []

    def fake_isfile(_):
        return True

    def fake_symlink(src, dst):
        calls.append((src, dst))

    def fake_islink(_):
        return True

    monkeypatch.setattr(entrypoint.path, "isfile", fake_isfile)
    monkeypatch.setattr(entrypoint.path, "islink", fake_islink)
    monkeypatch.setattr(entrypoint, "symlink", fake_symlink)

    entrypoint.create_dhparams(create=False)

    # New logic gates all actions behind `create=True`.
    assert calls == []


def test_create_dhparams_creates_file_with_openssl_when_create_is_true(monkeypatch):
    calls = []

    class DummyProc:
        def wait(self):
            return 0

    def fake_isfile(_):
        return False

    def fake_islink(_):
        return True

    def fake_popen(cmd, stdout, stderr, text):
        calls.append((cmd, stdout, stderr, text))
        return DummyProc()

    monkeypatch.setattr(entrypoint.path, "isfile", fake_isfile)
    monkeypatch.setattr(entrypoint.path, "islink", fake_islink)
    monkeypatch.setattr(entrypoint.subprocess, "Popen", fake_popen)

    entrypoint.create_dhparams(create=True)

    assert len(calls) == 1
    assert calls[0][0] == [
        "openssl",
        "dhparam",
        "-out",
        "/etc/letsencrypt/dhparams.pem",
        "4096",
    ]
