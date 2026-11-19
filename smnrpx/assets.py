from os import makedirs, path
from shutil import copy

WEB_ROOT = path.join(path.sep, "web_root")
DEFAULT_FILES = path.join(path.sep, "usr", "share", "nginx")


def populate_if_not_exists(domain_name: str, filename: str):
    web_root = path.join(WEB_ROOT, domain_name)
    target = path.join(web_root, filename)
    if path.isfile(target):
        return
    try:
        makedirs(web_root, exist_ok=True)
        copy(path.join(DEFAULT_FILES, filename), target)
    except OSError as error:
        # The default page files are optional: a web root that the app owns must not stop the proxy.
        print(f"⚠️ cannot copy the default {filename} to {web_root}: {error}")
