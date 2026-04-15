from pathlib import Path

from box import Box
from jinja2 import Environment, FileSystemLoader


def _render_smnrp_conf(domains: dict) -> str:
    env = Environment(
        loader=FileSystemLoader(str(Path(__file__).resolve().parents[1] / "templates")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("smnrp.conf.j2")
    return template.render(certrequest=False, domains=Box(domains))


def test_proxy_auth_request_internal_uri_is_used_directly():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "disable_https": True,
                "sans": [],
                "upstreams": {"api": ["api:8000"]},
                "locations": [
                    {
                        "proxy": {
                            "uri": "/",
                            "proto": "http",
                            "upstream": "api",
                            "path": "/",
                            "auth_request": "/auth/check/",
                        }
                    }
                ],
            }
        }
    )

    assert "auth_request /auth/check/;" in rendered
    assert "/__smnrpx_auth_request_proxy_0" not in rendered


def test_proxy_auth_request_external_url_uses_internal_helper_location():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "disable_https": True,
                "sans": [],
                "upstreams": {"api": ["api:8000"]},
                "locations": [
                    {
                        "proxy": {
                            "uri": "/",
                            "proto": "http",
                            "upstream": "api",
                            "path": "/",
                            "auth_request": "https://auth.example.org/check",
                        }
                    }
                ],
            }
        }
    )

    assert "location = /__smnrpx_auth_request_proxy_0 {" in rendered
    assert "proxy_pass https://auth.example.org/check;" in rendered
    assert "auth_request /__smnrpx_auth_request_proxy_0;" in rendered
    assert "proxy_pass_request_body off;" in rendered


def test_alias_auth_request_external_url_uses_internal_helper_location():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "disable_https": True,
                "sans": [],
                "locations": [
                    {
                        "alias": {
                            "uri": "/files/",
                            "path": "/data/files",
                            "auth_request": "https://auth.example.org/check-files",
                        }
                    }
                ],
            }
        }
    )

    assert "location = /__smnrpx_auth_request_alias_0 {" in rendered
    assert "proxy_pass https://auth.example.org/check-files;" in rendered
    assert "auth_request /__smnrpx_auth_request_alias_0;" in rendered


def test_oauth_url_external_applies_auth_request_to_all_locations():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "disable_https": True,
                "sans": [],
                "oauth_url": "https://proxy.auth.nexus.ethz.ch/oauth2/",
                "upstreams": {"api": ["api:8000"]},
                "locations": [
                    {
                        "proxy": {
                            "uri": "/",
                            "proto": "http",
                            "upstream": "api",
                            "path": "/",
                        }
                    },
                    {
                        "proxy": {
                            "uri": "/api/",
                            "proto": "http",
                            "upstream": "api",
                            "path": "/",
                        }
                    },
                ],
            }
        }
    )

    assert "location = /__smnrpx_oauth_auth {" in rendered
    assert "proxy_pass https://proxy.auth.nexus.ethz.ch/oauth2/auth;" in rendered
    assert "location /oauth2/ {" in rendered
    assert "proxy_pass https://proxy.auth.nexus.ethz.ch/oauth2/;" in rendered
    assert rendered.count("auth_request /__smnrpx_oauth_auth;") == 2
    assert (
        rendered.count("error_page 401 =302 /oauth2/start?rd=$scheme://$http_host$request_uri;")
        == 1
    )


def test_oauth_url_internal_uses_direct_auth_request_uri():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "disable_https": True,
                "sans": [],
                "oauth_url": "/oauth2/",
                "locations": [
                    {
                        "alias": {
                            "uri": "/",
                            "path": "/srv/www",
                        }
                    }
                ],
            }
        }
    )

    assert "auth_request /oauth2/auth;" in rendered
    assert "location = /__smnrpx_oauth_auth {" not in rendered
    assert "location /oauth2/ {" not in rendered
    assert "error_page 401 =302 /oauth2/start?rd=$scheme://$http_host$request_uri;" in rendered


def test_location_auth_request_overrides_global_oauth_url():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "disable_https": True,
                "sans": [],
                "oauth_url": "https://proxy.auth.nexus.ethz.ch/oauth2/",
                "upstreams": {"api": ["api:8000"]},
                "locations": [
                    {
                        "proxy": {
                            "uri": "/",
                            "proto": "http",
                            "upstream": "api",
                            "path": "/",
                            "auth_request": "/custom-auth/",
                        }
                    }
                ],
            }
        }
    )

    assert "auth_request /custom-auth/;" in rendered
    assert "auth_request /__smnrpx_oauth_auth;" not in rendered
    assert "error_page 401 =302 /oauth2/start?rd=$scheme://$http_host$request_uri;" not in rendered


def test_allow_tls1_2_enables_tls12_and_tls13():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "sans": [],
                "cert": "self-signed",
                "allow_tls1.2": True,
                "disable_ocsp_stapling": False,
            }
        }
    )

    assert "ssl_protocols TLSv1.2 TLSv1.3;" in rendered
    assert "ssl_protocols TLSv1.3;" not in rendered


def test_ocsp_stapling_is_enabled_by_default_for_letsencrypt_and_can_be_disabled():
    rendered_default = _render_smnrp_conf(
        {
            "example.org": {
                "sans": [],
                "allow_tls1.2": False,
                "disable_ocsp_stapling": False,
            }
        }
    )
    rendered_disabled = _render_smnrp_conf(
        {
            "example.org": {
                "sans": [],
                "allow_tls1.2": False,
                "disable_ocsp_stapling": True,
            }
        }
    )

    assert "ssl_stapling on;" in rendered_default
    assert "ssl_stapling_verify on;" in rendered_default
    assert "ssl_stapling on;" not in rendered_disabled
