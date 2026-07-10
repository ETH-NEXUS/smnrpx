from pathlib import Path
import re

from box import Box
from jinja2 import Environment, FileSystemLoader

from smnrpx.configuration import apply_defaults


def _render_smnrp_conf(
    domains: dict, certrequest: bool = False, with_defaults: bool = False
) -> str:
    cfg = Box({"domains": domains})
    if with_defaults:
        cfg = apply_defaults(cfg)
    env = Environment(
        loader=FileSystemLoader(str(Path(__file__).resolve().parents[1] / "templates")),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    template = env.get_template("smnrp.conf.j2")
    return template.render(certrequest=certrequest, domains=cfg.domains)


def _location_block(rendered: str, uri: str) -> str:
    match = re.search(rf"  location {re.escape(uri)} \{{\n(?P<body>.*?)\n  \}}", rendered, re.S)
    assert match is not None
    return match.group("body")


def test_certrequest_skips_disabled_https_domains():
    rendered = _render_smnrp_conf(
        {
            "http-only.example.org": {
                "disable_https": True,
                "sans": [],
                "upstreams": {},
                "locations": [],
            }
        },
        certrequest=True,
    )

    assert "http-only.example.org" not in rendered
    assert "server {" not in rendered


def test_certrequest_mixed_domains_only_renders_https_enabled_domains():
    rendered = _render_smnrp_conf(
        {
            "http-only.example.org": {
                "disable_https": True,
                "sans": [],
                "upstreams": {},
                "locations": [],
            },
            "secure.example.org": {
                "disable_https": False,
                "sans": [],
                "upstreams": {},
                "locations": [],
            },
        },
        certrequest=True,
    )

    assert "http-only.example.org" not in rendered
    assert "server_name secure.example.org;" in rendered
    assert "location /.well-known/acme-challenge/ {" in rendered
    assert rendered.count("server {") == 1


def test_large_client_header_buffers_default_is_rendered():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "disable_https": True,
                "sans": [],
            }
        }
    )

    assert "large_client_header_buffers 2 1k;" in rendered


def test_large_client_header_buffers_can_be_configured_per_domain():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "disable_https": True,
                "sans": [],
                "large_client_header_buffers": "4 16k",
            }
        }
    )

    assert "large_client_header_buffers 4 16k;" in rendered
    assert "large_client_header_buffers 2 1k;" not in rendered


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


def test_alias_internal_and_try_files_are_read_from_alias_config():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "disable_https": True,
                "sans": [],
                "locations": [
                    {
                        "alias": {
                            "uri": "/media/",
                            "path": "/srv/media",
                            "internal": True,
                            "try_files": True,
                        }
                    }
                ],
            }
        }
    )

    assert "location /media/ {" in rendered
    assert "internal;" in rendered
    assert "alias /srv/media;" in rendered
    assert "try_files $uri $uri/ /index.html;" in rendered


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
                    {
                        "alias": {
                            "uri": "/files/",
                            "path": "/srv/files",
                        }
                    },
                ],
            }
        }
    )

    assert "location = /__smnrpx_oauth_auth {" in rendered
    assert "proxy_pass https://proxy.auth.nexus.ethz.ch/oauth2/auth;" in rendered
    assert "proxy_set_header Host $http_host;" in rendered
    assert "proxy_set_header X-Real-IP $remote_addr;" in rendered
    assert "proxy_set_header X-Forwarded-Uri $request_uri;" in rendered
    assert "proxy_set_header X-Forwarded-Host $http_host;" in rendered
    assert "location /oauth2/ {" in rendered
    assert "proxy_pass https://proxy.auth.nexus.ethz.ch/oauth2/;" in rendered
    assert (
        "proxy_set_header X-Auth-Request-Redirect $scheme://$http_host$request_uri;"
        in rendered
    )
    assert rendered.count("auth_request /__smnrpx_oauth_auth;") == 3
    assert (
        rendered.count("error_page 401 =302 /oauth2/start?rd=$scheme://$http_host$request_uri;")
        == 3
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


def test_disable_cache_keeps_security_headers_in_location_context():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "sans": [],
                "disable_https": True,
                "upstreams": {"api": ["api:8000"]},
                "locations": [
                    {
                        "proxy": {
                            "uri": "/api/",
                            "proto": "http",
                            "upstream": "api",
                            "path": "/",
                            "disable_cache": True,
                        }
                    }
                ],
            }
        }
    )

    # Security headers are emitted in both server and location context.
    assert rendered.count('add_header Strict-Transport-Security "max-age=31536000; includeSubdomains; preload";') == 2
    assert rendered.count('add_header X-Frame-Options "SAMEORIGIN";') == 2
    assert rendered.count("add_header Referrer-Policy strict-origin-when-cross-origin;") == 2

    # disable_cache locations use the strict cache-control header and avoid duplicating the default one.
    assert rendered.count('add_header Cache-Control no-cache="Set-Cookie";') == 1
    assert "add_header Cache-Control 'private no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0';" in rendered


def test_domain_csp_is_emitted_only_when_defined():
    with_csp = _render_smnrp_conf(
        {
            "example.org": {
                "sans": [],
                "disable_https": True,
                "csp": "default-src 'self'",
            }
        }
    )
    without_csp = _render_smnrp_conf(
        {
            "example.org": {
                "sans": [],
                "disable_https": True,
            }
        }
    )

    assert 'add_header Content-Security-Policy "default-src \'self\'" always;' in with_csp
    assert "add_header Content-Security-Policy" not in without_csp


def test_proxy_csp_is_emitted_inside_proxy_location():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "sans": [],
                "disable_https": True,
                "upstreams": {"app": ["app:8000"]},
                "locations": [
                    {
                        "proxy": {
                            "uri": "/app/",
                            "proto": "http",
                            "upstream": "app",
                            "path": "/",
                            "csp": "default-src 'self' https: 'unsafe-inline'",
                        }
                    }
                ],
            }
        }
    )

    location_block = _location_block(rendered, "/app/")

    assert (
        'add_header Content-Security-Policy "default-src \'self\' https: \'unsafe-inline\'" always;'
        in location_block
    )


def test_proxy_csp_overrides_domain_csp_and_preserves_location_security_headers():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "sans": [],
                "disable_https": True,
                "csp": "default-src 'self'",
                "upstreams": {"app": ["app:8000"]},
                "locations": [
                    {
                        "proxy": {
                            "uri": "/app/",
                            "proto": "http",
                            "upstream": "app",
                            "path": "/",
                            "csp": "default-src 'self' https: data: 'unsafe-inline'",
                        }
                    }
                ],
            }
        }
    )

    location_block = _location_block(rendered, "/app/")

    assert rendered.count('add_header Content-Security-Policy "default-src \'self\'" always;') == 1
    assert (
        rendered.count(
            'add_header Content-Security-Policy "default-src \'self\' https: data: \'unsafe-inline\'" always;'
        )
        == 1
    )
    assert 'add_header Content-Security-Policy "default-src \'self\'" always;' not in location_block
    assert (
        'add_header Content-Security-Policy "default-src \'self\' https: data: \'unsafe-inline\'" always;'
        in location_block
    )
    assert 'add_header Strict-Transport-Security "max-age=31536000; includeSubdomains; preload";' in location_block
    assert "add_header Referrer-Policy strict-origin-when-cross-origin;" in location_block
    assert 'add_header X-Frame-Options "SAMEORIGIN";' in location_block
    assert "add_header X-Content-Type-Options nosniff;" in location_block
    assert 'add_header Cache-Control no-cache="Set-Cookie";' in location_block


def test_no_csp_header_is_emitted_without_domain_or_proxy_csp():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "sans": [],
                "disable_https": True,
                "upstreams": {"api": ["api:8000"]},
                "locations": [
                    {
                        "proxy": {
                            "uri": "/api/",
                            "proto": "http",
                            "upstream": "api",
                            "path": "/",
                        }
                    }
                ],
            }
        }
    )

    assert "add_header Content-Security-Policy" not in rendered


def test_absolute_redirect_can_be_disabled_per_domain():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "disable_https": True,
                "sans": [],
                "absolute_redirect": False,
            }
        }
    )

    assert "absolute_redirect off;" in rendered
    assert "absolute_redirect on;" not in rendered


def test_absolute_redirect_can_be_enabled_explicitly_per_domain():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "disable_https": True,
                "sans": [],
                "absolute_redirect": True,
            }
        }
    )

    assert "absolute_redirect on;" in rendered


def test_redirect_www_adds_generated_server_name_and_https_redirect():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "redirect_www": True,
            }
        },
        with_defaults=True,
    )

    assert "server_name example.org www.example.org;" in rendered
    assert "if ($host = www.example.org) {" in rendered
    assert "return 301 https://example.org$request_uri;" in rendered


def test_redirect_www_uses_exposed_https_port_in_redirect():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "redirect_www": True,
                "ports": {
                    "exposed_https": 8443,
                },
            }
        },
        with_defaults=True,
    )

    assert "return 301 https://example.org:8443$request_uri;" in rendered


def test_redirect_www_uses_http_when_https_is_disabled():
    rendered = _render_smnrp_conf(
        {
            "example.org": {
                "redirect_www": True,
                "disable_https": True,
            }
        },
        with_defaults=True,
    )

    assert "server_name example.org www.example.org;" in rendered
    assert "return 301 http://example.org$request_uri;" in rendered
    assert "return 301 https://example.org$request_uri;" not in rendered
