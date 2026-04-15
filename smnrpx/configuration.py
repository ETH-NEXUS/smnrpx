from os import environ

import yamale
import yaml
from box import Box
from yamale.yamale_error import YamaleError

from smnrpx.constants import DEFAULTS, ENV_VAR_PATTERN


def apply_defaults(cfg: Box) -> Box:
    if "domains" not in cfg:
        return cfg

    for domain in cfg.domains.values():
        for key, value in DEFAULTS.items():
            if key not in domain:
                domain[key] = value
    return cfg


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
