import re
import signal
import subprocess
from os import path

from jinja2 import Environment

from smnrpx.constants import SMNRP_NGINX_CONFIG


def print_context(filename: str, line_no: int, context: int = 5):
    with open(filename, encoding="utf-8") as handle:
        lines = handle.readlines()

    start = max(0, line_no - context - 1)
    end = min(len(lines), line_no + context)

    for idx in range(start, end):
        prefix = ">" if idx == line_no - 1 else " "
        print(f"{prefix}{idx + 1:5}: {lines[idx].rstrip()}")


def check_nginx_syntax():
    nginx = subprocess.Popen(
        ["nginx", "-t"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if nginx.wait() != 0:
        out, err = nginx.communicate(timeout=1)
        print("❌ nginx configuration issues:")
        print(f"{out}\n{err}")
        pattern = re.compile(rf"{re.escape(SMNRP_NGINX_CONFIG)}:(\d+)")
        for line in err.splitlines():
            match = pattern.search(line)
            if match:
                print_context(SMNRP_NGINX_CONFIG, int(match.group(1)))
                break
        raise SystemExit(2)

    print("✅ nginx configuration is ok")


def prepare_nginx_for_cert_request(cfg, env: Environment):
    with open(SMNRP_NGINX_CONFIG, "w", encoding="utf-8") as config_file:
        template = env.get_template("smnrp.conf.j2")
        config_file.write(template.render(certrequest=True, domains=cfg.domains))
    check_nginx_syntax()

    nginx = subprocess.Popen(
        ["nginx", "-g", "daemon off;"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if nginx.poll() is not None:
        out, err = nginx.communicate(timeout=1)
        raise RuntimeError(f"nginx failed to start.\nstdout:\n{out}\nstderr:\n{err}")
    return nginx


def kill_nginx(nginx):
    if nginx.poll() is None:
        nginx.send_signal(signal.SIGTERM)
    try:
        nginx.wait(timeout=3)
    except subprocess.TimeoutExpired:
        nginx.kill()
        nginx.wait()


def remove_default_nginx_conf(nginx_config_base: str):
    default_conf = path.join(nginx_config_base, "default.conf")
    if path.isfile(default_conf):
        from os import remove

        remove(default_conf)
