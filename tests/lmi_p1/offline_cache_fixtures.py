from __future__ import annotations

import hashlib
import json
from pathlib import Path


SCHEMA = "lmi-p1-offline-cache/v2"
REPOSITORY_URLS = (
    "http://dl-cdn.alpinelinux.org/alpine/edge/community",
    "http://dl-cdn.alpinelinux.org/alpine/edge/main",
    "http://dl-cdn.alpinelinux.org/alpine/edge/testing",
    "http://mirror.postmarketos.org/postmarketos/main",
)
PMBOOTSTRAP_COMMIT = "ce76febabd983db6445fa9a8b75d601970b2f436"
PMBOOTSTRAP_VERSION = "3.11.1"
PMAPORTS_COMMIT = "6fb3a1e5eb21c809891645a2ba5ae11fa788e032"
PMAPORTS_TREE = "749f154b6f154f86133e7c7616074aa9eb876f2e"


def canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def write_offline_cache(root: Path) -> tuple[Path, dict[str, object]]:
    cache = root / "offline-cache"
    work = cache / "work"
    for name in (
        "cache_apk_aarch64",
        "cache_apk_x86_64",
        "cache_distfiles",
        "cache_http",
    ):
        (work / name).mkdir(parents=True, exist_ok=True)
    (work / "version").write_bytes(b"8\n")

    trust_root = root / "pmbootstrap/pmb/data/keys"
    trust_root.mkdir(parents=True, exist_ok=True)
    signer_payloads = {
        "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub": b"fixture alpine signing key\n",
        "build.postmarketos.org.rsa.pub": b"fixture postmarketOS signing key\n",
    }
    for basename, payload in signer_payloads.items():
        (trust_root / basename).write_bytes(payload)

    repositories: list[dict[str, object]] = []
    for architecture in ("aarch64", "x86_64"):
        directory = work / f"cache_apk_{architecture}"
        for basename, payload in signer_payloads.items():
            (directory / basename).write_bytes(payload)
        for url in REPOSITORY_URLS:
            url_digest = hashlib.sha1(
                url.encode("utf-8"), usedforsecurity=False
            ).hexdigest()
            index = directory / f"APKINDEX.{url_digest[:8]}.tar.gz"
            key = directory / (
                "build.postmarketos.org.rsa.pub"
                if "postmarketos.org" in url
                else "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"
            )
            index.write_bytes(f"index:{architecture}:{url}\n".encode("ascii"))
            repositories.append(
                {
                    "architecture": architecture,
                    "index_path": f"work/cache_apk_{architecture}/{index.name}",
                    "index_sha256": hashlib.sha256(index.read_bytes()).hexdigest(),
                    "index_size": index.stat().st_size,
                    "signer_key_path": f"work/cache_apk_{architecture}/{key.name}",
                    "signer_key_sha256": hashlib.sha256(key.read_bytes()).hexdigest(),
                    "url": url,
                }
            )

    http_payload = b"fixture authenticated apk-tools-static package\n"
    http_path = work / "cache_http/apk-tools-static-3.0.6-r0.apk"
    http_path.write_bytes(http_payload)
    http_signer = work / (
        "cache_apk_x86_64/"
        "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub"
    )
    http_artifacts = [
        {
            "kind": "apk-tools-static",
            "name": "apk-tools-static",
            "path": "work/cache_http/apk-tools-static-3.0.6-r0.apk",
            "sha256": hashlib.sha256(http_payload).hexdigest(),
            "signer_key_path": http_signer.relative_to(cache).as_posix(),
            "signer_key_sha256": hashlib.sha256(
                http_signer.read_bytes()
            ).hexdigest(),
            "size": len(http_payload),
            "url": (
                "http://dl-cdn.alpinelinux.org/alpine/edge/main/x86_64/"
                "apk-tools-static-3.0.6-r0.apk"
            ),
            "version": "3.0.6-r0",
        }
    ]

    distfile_payload = b"fixture pinned linux-xiaomi-lmi source archive\n"
    distfile_path = work / "cache_distfiles/linux-xiaomi-lmi-source.tar.gz"
    distfile_path.write_bytes(distfile_payload)
    distfiles = [
        {
            "apkbuild_sha512": "a" * 128,
            "path": "work/cache_distfiles/linux-xiaomi-lmi-source.tar.gz",
            "sha256": hashlib.sha256(distfile_payload).hexdigest(),
            "size": len(distfile_payload),
            "url": (
                "https://github.com/LineageOS/android_kernel_xiaomi_sm8250/"
                "archive/a5b3099017ae581aae8bf597b2f9c8c765026af1.tar.gz"
            ),
        }
    ]

    members = []
    for path in sorted(item for item in work.rglob("*") if item.is_file()):
        relative = path.relative_to(cache).as_posix()
        payload = path.read_bytes()
        members.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    manifest: dict[str, object] = {
        "distfiles": distfiles,
        "external_apks": [],
        "http_artifacts": http_artifacts,
        "members": members,
        "pins": {
            "pmbootstrap": {
                "commit": PMBOOTSTRAP_COMMIT,
                "version": PMBOOTSTRAP_VERSION,
                "work_version": 8,
            },
            "pmaports": {
                "channel": "edge",
                "commit": PMAPORTS_COMMIT,
                "tree": PMAPORTS_TREE,
            },
        },
        "repositories": sorted(
            repositories,
            key=lambda item: (str(item["architecture"]), str(item["url"])),
        ),
        "schema": SCHEMA,
    }
    manifest["aggregate_sha256"] = hashlib.sha256(canonical(manifest)).hexdigest()
    (cache / "offline-cache.manifest.json").write_bytes(canonical(manifest))
    for path in cache.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    return cache, manifest


def offline_binding(cache: Path, manifest: dict[str, object]) -> dict[str, str]:
    payload = (cache / "offline-cache.manifest.json").read_bytes()
    return {
        "aggregate_sha256": str(manifest["aggregate_sha256"]),
        "manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "schema": SCHEMA,
    }
