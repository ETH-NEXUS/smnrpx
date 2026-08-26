from os import environ

import yamale
import yaml
from box import Box
from yamale.yamale_error import YamaleError

from smnrpx.constants import DEFAULTS, ENV_VAR_PATTERN
from smnrpx.domains import get_effective_sans, get_redirect_hosts


def apply_defaults(cfg: Box) -> Box:
    if "domains" not in cfg:
        return cfg

    for domain_name, domain in cfg.domains.items():
        for key, value in DEFAULTS.items():
            if key not in domain:
                domain[key] = value
        redirect_hosts = get_redirect_hosts(domain_name, domain)
        if redirect_hosts:
            domain["redirect_hosts"] = redirect_hosts
            domain["sans"] = get_effective_sans(domain_name, domain)
    return cfg


def drop_unresolved_domains(config):
    """Drop domain blocks whose name did not resolve to an actual domain name.

    A block keyed on '${SOME_VAR}' stays in the configuration as long as the
    variable is unset, and becomes an empty name once it is set to an empty
    value. Both would end up as a broken nginx 'server_name', so such blocks are
    treated as not configured and skipped.
    """
    domains = config.get("domains") if isinstance(config, dict) else None
    if not isinstance(domains, dict):
        return config

    kept = {}
    for domain_name, domain in domains.items():
        if isinstance(domain_name, str):
            if not domain_name.strip():
                print("⏭️ Skipping domain block without a domain name")
                continue
            if ENV_VAR_PATTERN.search(domain_name):
                print(f"⏭️ Skipping domain block '{domain_name}', it is not set")
                continue
        kept[domain_name] = domain

    if domains and not kept:
        print("❌ No domain is left after resolving the domain names")
        print("👉 Please set the environment variables used as domain names")
        raise SystemExit(4)

    config["domains"] = kept
    return config


def expand_env_vars(value):
    if isinstance(value, str):
        exact_match = ENV_VAR_PATTERN.fullmatch(value)
        if exact_match:
            env_name = exact_match.group(1)
            env_value = environ.get(env_name)
            if env_value is None:
                return value
            if env_value == "":
                return ""

            try:
                return yaml.safe_load(env_value)
            except yaml.YAMLError:
                return env_value

        return ENV_VAR_PATTERN.sub(lambda m: environ.get(m.group(1), m.group(0)), value)
    if isinstance(value, dict):
        expanded = {}
        for key, item in value.items():
            expanded_key = expand_env_vars(key) if isinstance(key, str) else key
            if expanded_key in expanded:
                raise ValueError(f"Duplicate key after environment interpolation: {expanded_key!r}")
            expanded[expanded_key] = expand_env_vars(item)
        return expanded
    if isinstance(value, list):
        return [expand_env_vars(v) for v in value]
    return value


def check_smnrp_config(config):
    try:
        schema = yamale.make_schema("/smnrp_schema.yml")
        config_data = yamale.make_data(content=yaml.safe_dump(config))
        yamale.validate(schema, config_data)
        print("✅ SMNRP configuration is valid")
    except YamaleError as exc:
        print("❌ SMNRP configuration validation failed, findings:")
        for result in exc.results:
            for error in result.errors:
                print("-", error)
        raise SystemExit(4) from exc
