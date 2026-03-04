from os import environ

import yamale
import yaml
from box import Box
from yamale.yamale_error import YamaleError

from smnrpx.constants import DEFAULTS, ENV_VAR_PATTERN


def apply_defaults(cfg: Box) -> Box:
    for key, value in DEFAULTS.items():
        if key not in cfg:
            cfg[key] = value
    return cfg


def expand_env_vars(value):
    if isinstance(value, str):
        return ENV_VAR_PATTERN.sub(lambda m: environ.get(m.group(1), m.group(0)), value)
    if isinstance(value, dict):
        return {k: expand_env_vars(v) for k, v in value.items()}
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
