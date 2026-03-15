import hashlib
import json
from pathlib import Path


def _stable_signature(domain_name: str, domain) -> str:
    # Sort SANs so ordering in YAML doesn't change the hash.
    sans_norm = sorted(str(s).strip() for s in (domain.get("sans", [])))
    cert = domain.cert if "cert" in domain else ""
    return f"{domain_name}|{cert}|{json.dumps(sans_norm, separators=(',', ':'), ensure_ascii=False)}"


def compute_domain_hash(domain_name: str, domain) -> str:
    sig = _stable_signature(domain_name, domain)
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()


def compute_certificate_request_hash(primary_domain: str, additional_domains: list[str]) -> str:
    sig = json.dumps(
        {
            "primary_domain": primary_domain,
            "additional_domains": sorted(str(domain).strip() for domain in additional_domains),
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(sig.encode("utf-8")).hexdigest()


def store_hash_value(store_path: str, key: str, value: str) -> str:
    store_path_obj = Path(store_path)

    if store_path_obj.exists():
        data = json.loads(store_path_obj.read_text(encoding="utf-8") or "{}")
        if not isinstance(data, dict):
            raise TypeError("Hash store file is not a JSON object/dict.")
    else:
        data = {}

    data[key] = value

    store_path_obj.parent.mkdir(parents=True, exist_ok=True)
    tmp = store_path_obj.with_suffix(store_path_obj.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(store_path_obj)

    return value


def store_domain_hash(store_path: str, domain_name: str, domain) -> str:
    new_hash = compute_domain_hash(domain_name, domain)
    return store_hash_value(store_path, domain_name, new_hash)


def get_domain_hash(store_path: str, domain_name: str) -> str | None:
    store_path_obj = Path(store_path)
    if not store_path_obj.exists():
        return None

    data = json.loads(store_path_obj.read_text(encoding="utf-8") or "{}")
    if not isinstance(data, dict):
        raise TypeError("Hash store file is not a JSON object/dict.")

    value = data.get(domain_name)
    return str(value) if value is not None else None
