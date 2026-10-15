import os

import pytest

from app import paths
from app.updates import github

NETWORK = os.environ.get("LAZEYKA_NO_NETWORK") != "1"


def test_git_blob_sha1_matches_git():
    # git hash-object для "hello\n"
    assert github.git_blob_sha1(b"hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a"


@pytest.mark.skipif(not NETWORK, reason="без сети")
def test_vendored_proxy_matches_upstream_tag():
    entries = {e["path"]: e["sha"] for e in github.tree("Flowseal/tg-ws-proxy", "v1.11.2")
               if e.get("type") == "blob" and e["path"].startswith("proxy/") and e["path"].endswith(".py")}
    vendored = paths.resource_dir() / "app" / "vendor" / "tgws_proxy"
    assert entries, "в дереве тега нет proxy/*.py"
    for path, sha in entries.items():
        local = vendored / path.split("/", 1)[1]
        assert local.is_file(), path
        assert github.git_blob_sha1(local.read_bytes()) == sha, path


@pytest.mark.skipif(not NETWORK, reason="без сети")
def test_latest_releases_have_checksums():
    zapret = github.latest_release("Flowseal/zapret-discord-youtube")
    zips = [a for a in zapret["assets"] if a["name"].endswith(".zip")]
    assert zips and all(a["sha256"] for a in zips)
    tg = github.latest_release("Flowseal/tg-ws-proxy")
    assert tg["tag"].startswith("v")
