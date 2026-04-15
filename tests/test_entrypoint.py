import json

import pytest
from box import Box

import entrypoint
from smnrpx import certificates
from smnrpx import configuration
from smnrpx import nginx_runtime


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


def test_apply_defaults_sets_missing_and_preserves_existing_per_domain():
    cfg = Box({"domains": {"api.example.org": {"server_tokens": "on", "allow_tls1.2": True}}})
    applied = entrypoint.apply_defaults(cfg)

    domain = applied.domains["api.example.org"]
    assert domain["server_tokens"] == "on"
    assert domain["allow_tls1.2"] is True
    for key, value in entrypoint.DEFAULTS.items():
        assert key in domain
        if key not in {"server_tokens", "allow_tls1.2"}:
            assert domain[key] == value

    assert "server_tokens" not in applied


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

    def fake_isfile(file_path):
        return file_path == "/usr/share/nginx/dhparams.pem"

    def fake_symlink(src, dst):
        calls.append((src, dst))

    monkeypatch.setattr(certificates.path, "isfile", fake_isfile)
    monkeypatch.setattr(certificates.path, "islink", lambda _: False)
    monkeypatch.setattr(certificates.path, "isdir", lambda _: False)
    monkeypatch.setattr(certificates, "symlink", fake_symlink)

    entrypoint.create_dhparams(create=False)

    assert calls == [("/usr/share/nginx/dhparams.pem", "/etc/letsencrypt/dhparams.pem")]


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

    monkeypatch.setattr(certificates.path, "isfile", fake_isfile)
    monkeypatch.setattr(certificates.path, "islink", fake_islink)
    monkeypatch.setattr(certificates.subprocess, "Popen", fake_popen)

    entrypoint.create_dhparams(create=True)

    assert len(calls) == 1
    assert calls[0][0] == [
        "openssl",
        "dhparam",
        "-out",
        "/etc/letsencrypt/dhparams.pem",
        "4096",
    ]


def test_expand_env_vars_expands_nested_values_and_keeps_missing(monkeypatch):
    monkeypatch.setenv("SMNRPX_HOST", "example.org")

    raw = {
        "a": "${SMNRPX_HOST}",
        "nested": ["https://${SMNRPX_HOST}", {"x": "${MISSING_VAR}"}],
    }

    expanded = configuration.expand_env_vars(raw)

    assert expanded["a"] == "example.org"
    assert expanded["nested"][0] == "https://example.org"
    assert expanded["nested"][1]["x"] == "${MISSING_VAR}"


def test_expand_env_vars_expands_mapping_keys(monkeypatch):
    monkeypatch.setenv("SMNRPX_DOMAIN", "api.example.org")

    raw = {
        "domains": {
            "${SMNRPX_DOMAIN}": {
                "cert": "letsencrypt",
            }
        }
    }

    expanded = configuration.expand_env_vars(raw)

    assert "api.example.org" in expanded["domains"]
    assert expanded["domains"]["api.example.org"]["cert"] == "letsencrypt"


def test_expand_env_vars_raises_on_duplicate_keys_after_expansion(monkeypatch):
    monkeypatch.setenv("SMNRPX_DOMAIN", "api.example.org")

    raw = {
        "domains": {
            "api.example.org": {"cert": "own"},
            "${SMNRPX_DOMAIN}": {"cert": "letsencrypt"},
        }
    }

    with pytest.raises(ValueError, match="Duplicate key after environment interpolation"):
        configuration.expand_env_vars(raw)


def test_create_dhparams_noop_when_target_exists(monkeypatch):
    calls = []

    def fake_isfile(file_path):
        return file_path == "/etc/letsencrypt/dhparams.pem"

    def fake_popen(*_args, **_kwargs):
        calls.append("popen")
        raise AssertionError("Popen must not be called when dhparams exists")

    def fake_symlink(*_args, **_kwargs):
        calls.append("symlink")
        raise AssertionError("Symlink must not be called when dhparams exists")

    monkeypatch.setattr(certificates.path, "isfile", fake_isfile)
    monkeypatch.setattr(certificates.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(certificates, "symlink", fake_symlink)

    entrypoint.create_dhparams(create=True)

    assert calls == []


def test_create_dhparams_raises_when_openssl_fails(monkeypatch):
    class DummyProc:
        def wait(self):
            return 1

        def communicate(self, timeout):
            return ("out", "err")

    monkeypatch.setattr(certificates.path, "isfile", lambda _: False)
    monkeypatch.setattr(certificates.subprocess, "Popen", lambda *_args, **_kwargs: DummyProc())

    with pytest.raises(SystemExit) as exc:
        entrypoint.create_dhparams(create=True)
    assert exc.value.code == 6


def test_handle_cert_request_builds_d_argument_without_trailing_comma(monkeypatch):
    calls = []

    def fake_run(cmd, check):
        calls.append((cmd, check))

    monkeypatch.setattr(certificates, "store_hash_value", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(certificates.subprocess, "run", fake_run)
    monkeypatch.setattr(certificates.path, "isdir", lambda _: False)

    grouped_domains = {"example.org": [{"domain": "api.example.org", "type": "vhost"}]}

    entrypoint.handle_cert_request(grouped_domains)

    assert len(calls) == 1
    cmd, check = calls[0]
    assert check is True
    d_idx = cmd.index("-d")
    assert cmd[d_idx + 1] == "api.example.org"


def test_handle_cert_request_skips_unchanged_requests(monkeypatch):
    calls = []

    monkeypatch.setattr(certificates, "get_domain_hash", lambda *_args, **_kwargs: "same-hash")
    monkeypatch.setattr(certificates, "compute_certificate_request_hash", lambda *_args, **_kwargs: "same-hash")
    monkeypatch.setattr(certificates.path, "isfile", lambda file_path: file_path == "/etc/letsencrypt/live/api.example.org/fullchain.pem")
    monkeypatch.setattr(certificates.subprocess, "run", lambda *args, **kwargs: calls.append((args, kwargs)))

    grouped_domains = {"example.org": [{"domain": "api.example.org", "type": "vhost"}]}

    entrypoint.handle_cert_request(grouped_domains)

    assert calls == []


def test_handle_cert_request_stores_hash_after_success(monkeypatch):
    stored = []

    monkeypatch.setattr(certificates, "get_domain_hash", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(certificates, "compute_certificate_request_hash", lambda *_args, **_kwargs: "new-hash")
    monkeypatch.setattr(certificates, "store_hash_value", lambda *args: stored.append(args))
    monkeypatch.setattr(certificates.path, "isfile", lambda *_: False)
    monkeypatch.setattr(certificates.path, "isdir", lambda *_: False)
    monkeypatch.setattr(certificates.subprocess, "run", lambda *_args, **_kwargs: None)

    grouped_domains = {"example.org": [{"domain": "api.example.org", "type": "vhost"}]}

    entrypoint.handle_cert_request(grouped_domains)

    assert stored == [("/etc/letsencrypt/live/domain_hashes.json", "example.org", "new-hash")]


def test_handle_cert_request_cleans_up_on_certbot_failure(monkeypatch):
    removed_dirs = []

    def fake_run(*_args, **_kwargs):
        raise certificates.subprocess.CalledProcessError(returncode=1, cmd="certbot")

    def fake_isdir(file_path):
        return file_path == "/etc/letsencrypt/live/api.example.org"

    monkeypatch.setattr(certificates.subprocess, "run", fake_run)
    monkeypatch.setattr(certificates.path, "isdir", fake_isdir)
    monkeypatch.setattr(certificates, "rmtree", lambda p: removed_dirs.append(p))

    grouped_domains = {"example.org": [{"domain": "api.example.org", "type": "vhost"}]}

    with pytest.raises(SystemExit, match="3"):
        entrypoint.handle_cert_request(grouped_domains)

    assert removed_dirs == ["/etc/letsencrypt/live/api.example.org"]


def test_remove_default_nginx_conf_removes_existing_file(tmp_path):
    base = tmp_path / "conf.d"
    base.mkdir(parents=True)
    default_conf = base / "default.conf"
    default_conf.write_text("server {}", encoding="utf-8")

    nginx_runtime.remove_default_nginx_conf(str(base))

    assert not default_conf.exists()
