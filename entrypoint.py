#! /usr/bin/env python3
from os import path

from smnrpx.app import main
from smnrpx.assets import populate_if_not_exists
from smnrpx.certificates import cert_renew, create_dhparams, handle_cert_request
from smnrpx.configuration import apply_defaults, check_smnrp_config, expand_env_vars
from smnrpx.constants import (
    CERT_RENEW_TIMEOUT,
    DEFAULTS,
    DOMAIN_HASHES,
    DOMAIN_REGEX,
    ENV_VAR_PATTERN,
    LIVE,
    NGINX_CONFIG_BASE,
    NGINX_DOT_CONF,
    SMNRP_CONFIG,
    SMNRP_NGINX_CONFIG,
)
from smnrpx.domains import get_grouped_domains
from smnrpx.hashing import compute_domain_hash, get_domain_hash, store_domain_hash
from smnrpx.nginx_runtime import check_nginx_syntax, kill_nginx, prepare_nginx_for_cert_request

__all__ = [
    "LIVE",
    "DOMAIN_HASHES",
    "SMNRP_CONFIG",
    "NGINX_DOT_CONF",
    "NGINX_CONFIG_BASE",
    "SMNRP_NGINX_CONFIG",
    "CERT_RENEW_TIMEOUT",
    "DOMAIN_REGEX",
    "ENV_VAR_PATTERN",
    "DEFAULTS",
    "compute_domain_hash",
    "store_domain_hash",
    "get_domain_hash",
    "populate_if_not_exists",
    "check_nginx_syntax",
    "check_smnrp_config",
    "cert_renew",
    "create_dhparams",
    "apply_defaults",
    "get_grouped_domains",
    "prepare_nginx_for_cert_request",
    "kill_nginx",
    "handle_cert_request",
    "expand_env_vars",
    "main",
    "path",
]

if __name__ == "__main__":
    main()
