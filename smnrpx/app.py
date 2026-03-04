import subprocess
from os import environ, execvp, fork, makedirs, path, remove
from pathlib import Path
from sys import argv

import yaml
from box import Box
from jinja2 import Environment, FileSystemLoader

from smnrpx.assets import populate_if_not_exists
from smnrpx.certificates import cert_renew, create_dhparams, handle_cert_request
from smnrpx.configuration import apply_defaults, check_smnrp_config, expand_env_vars
from smnrpx.constants import (
    DOMAIN_HASHES,
    LIVE,
    NGINX_CONFIG_BASE,
    NGINX_DOT_CONF,
    SMNRP_CONFIG,
    SMNRP_NGINX_CONFIG,
)
from smnrpx.domains import get_grouped_domains
from smnrpx.hashing import compute_domain_hash, get_domain_hash, store_domain_hash
from smnrpx.nginx_runtime import (
    check_nginx_syntax,
    kill_nginx,
    prepare_nginx_for_cert_request,
    remove_default_nginx_conf,
)


def _resolve_config_path() -> str:
    if "SMNRP" in environ:
        config_path = path.join(path.sep, "tmp", "smnrp.yml")
        env_config = environ.get("SMNRP")
        if env_config:
            out_path = Path(config_path)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(env_config, encoding="utf-8")
            print("✅ Take config from environment variable 'SMNRP'")
        return config_path

    if not path.isfile(SMNRP_CONFIG):
        print("❌ SMNRP config is missing")
        print("👉 Please configure the config in docker-compose.yml:")
        print("configs:")
        print("  smnrp:")
        print("    file: ./smnrp.yml")
        print("services:")
        print("  ws:")
        print("    configs:")
        print("      - source: smnrp")
        print(f"        target: {SMNRP_CONFIG}")
        raise SystemExit(1)

    return SMNRP_CONFIG


def _load_config(config_path: str) -> Box:
    with open(config_path, encoding="utf-8") as config_file:
        config = expand_env_vars(yaml.safe_load(config_file))
    check_smnrp_config(config)
    return apply_defaults(Box(config))


def _prepare_auth_files(domain_name: str, domain):
    if "locations" not in domain:
        return

    for _location in domain.locations:
        _, location = next(iter(_location.items()))
        if "auth" not in location:
            continue

        auth_config = path.join(
            NGINX_CONFIG_BASE,
            f".auth_{domain_name}{location.uri.replace(path.sep, '_')}",
        )

        if path.isfile(auth_config):
            remove(auth_config)

        for auth in location.auth:
            try:
                print(
                    f"👤 enable authentication on '{domain_name}{location.uri}' for user '{auth.user}', {auth_config}"
                )
                subprocess.run(
                    [
                        "htpasswd",
                        "-b",
                        *([] if path.isfile(auth_config) else ["-c"]),
                        auth_config,
                        auth.user,
                        auth.password,
                    ],
                    check=True,
                )
            except subprocess.CalledProcessError as exc:
                print(f"❌ Cannot create auth file for '{auth_config}'")
                raise SystemExit(5) from exc


def _process_domain_certificates(cfg: Box, env: Environment):
    for domain_name, domain in cfg.domains.items():
        populate_if_not_exists(domain_name, "index.html")
        populate_if_not_exists(domain_name, "favicon.ico")
        populate_if_not_exists(domain_name, "background.jpg")
        _prepare_auth_files(domain_name, domain)

        if "disable_https" in domain and domain.disable_https:
            print(f"⚠️ HTTPS is disabled for domain '{domain_name}'")
            new_hash = compute_domain_hash(domain_name, domain)
            old_hash = get_domain_hash(DOMAIN_HASHES, domain_name)
            if new_hash == old_hash and path.isfile(path.join(LIVE, domain_name, "fullchain.pem")):
                continue
            store_domain_hash(DOMAIN_HASHES, domain_name, domain)
            continue

        if "cert" in domain and domain.cert == "self-signed":
            print(f"✅ using self-signed certificate for domain '{domain_name}'")
            live = f"{LIVE}/{domain_name}"
            makedirs(live, exist_ok=True)
            csr_config = path.join(live, "csr.conf")
            with open(csr_config, "w", encoding="utf-8") as csr:
                template = env.get_template("csr.conf.j2")
                csr.write(template.render(domain_name=domain_name, domain=domain))
            try:
                cmd = [
                    "openssl",
                    "req",
                    "-x509",
                    "-nodes",
                    "-days",
                    "3650",
                    "-newkey",
                    "rsa:4096",
                    "-keyout",
                    path.join(live, "privkey.pem"),
                    "-out",
                    path.join(live, "fullchain.pem"),
                    "-config",
                    path.join(live, "csr.conf"),
                ]
                subprocess.run(cmd, check=True)
            except subprocess.CalledProcessError as exc:
                print(f"❌ Cannot create self-signed certificate for domain '{domain_name}'")
                print("Certificate Signing Request Config:")
                with open(path.join(live, "csr.conf"), encoding="utf-8") as handle:
                    print(handle.read())
                raise SystemExit(7) from exc
        elif "cert" in domain and domain.cert == "own":
            print(f"✅ using own certificate for domain '{domain_name}'")


def _render_nginx_config(cfg: Box, env: Environment):
    with open(NGINX_DOT_CONF, "w", encoding="utf-8") as config_file:
        template = env.get_template("nginx.conf.j2")
        config_file.write(template.render(modules=cfg.get("modules", None), nginx=cfg.get("nginx", None)))


def _render_final_smnrp_conf(cfg: Box, env: Environment):
    with open(SMNRP_NGINX_CONFIG, "w", encoding="utf-8") as config_file:
        template = env.get_template("smnrp.conf.j2")
        config_file.write(template.render(certrequest=False, domains=cfg.domains))


def _exec_foreground_process():
    pid = fork()
    if pid == 0:
        cert_renew()
        return

    args = argv[1:]
    if args:
        print(f"🙌 Executing {' '.join(args)}...")
        execvp(args[0], args)

    print("🙌 Starting nginx...")
    execvp("nginx", ["nginx", "-g", "daemon off;"])


def main():
    print("🚀 Start SMNRP 🚀")

    config_path = _resolve_config_path()
    cfg = _load_config(config_path)
    env = Environment(loader=FileSystemLoader("templates"), trim_blocks=True, lstrip_blocks=True)

    remove_default_nginx_conf(NGINX_CONFIG_BASE)
    create_dhparams(
        cfg.nginx.create_dhparams if "nginx" in cfg and "create_dhparams" in cfg.nginx else False
    )

    _render_nginx_config(cfg, env)

    nginx = prepare_nginx_for_cert_request(cfg, env)
    handle_cert_request(get_grouped_domains(cfg))
    kill_nginx(nginx)

    _process_domain_certificates(cfg, env)
    _render_final_smnrp_conf(cfg, env)
    check_nginx_syntax()

    _exec_foreground_process()
