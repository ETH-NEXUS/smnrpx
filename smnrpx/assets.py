from os import makedirs, path
from shutil import copy


def populate_if_not_exists(domain_name: str, filename: str):
    web_root = path.join(path.sep, "web_root", domain_name)
    makedirs(web_root, exist_ok=True)
    src_dir = path.join(path.sep, "usr", "share", "nginx")
    target = path.join(web_root, filename)
    if not path.isfile(target):
        copy(path.join(src_dir, filename), target)
