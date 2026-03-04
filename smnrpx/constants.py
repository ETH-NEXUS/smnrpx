import re
from os import path

LIVE = path.join("/", "etc", "letsencrypt", "live")
DOMAIN_HASHES = path.join(LIVE, "domain_hashes.json")
SMNRP_CONFIG = path.join(path.sep, "run", "configs", "smnrp.yml")
NGINX_DOT_CONF = path.join("/", "etc", "nginx", "nginx.conf")
NGINX_CONFIG_BASE = path.join("/", "etc", "nginx", "conf.d")
SMNRP_NGINX_CONFIG = path.join(NGINX_CONFIG_BASE, "smnrp.conf")
CERT_RENEW_TIMEOUT = 24 * 60 * 60
DOMAIN_REGEX = re.compile(r"^(?:(?P<sub>.+)\.)?(?P<main>[^.]+\.[^.]+)$")
ENV_VAR_PATTERN = re.compile(r"\$\{([^}]+)\}")

DEFAULTS = {
    "server_tokens": "off",
    "proxy_buffer_size": "32k",
    "client_max_body_size": "1m",
    "client_body_buffer_size": "1k",
    "allow_tls1_2": False,
    "disable_ocsp_stapling": False,
}
