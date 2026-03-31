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
