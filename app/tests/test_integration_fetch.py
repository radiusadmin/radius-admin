"""Download of second-factor provider builds (SPEC section 29): fixed address, checked against
the catalog when it lists the build, status file for the portal. The network is mocked."""
import hashlib
import io
import json
import os

import pytest

from radius_admin import integration_fetch as f

BUILD = b"duo build " * 100


class FakeResponse(io.BytesIO):
    def __init__(self, data, url):
        super().__init__(data)
        self._url = url

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def cfg(tmp_path):
    d = tmp_path / "integrations"
    d.mkdir()
    return {"integration_dir": str(d), "integration_catalog": str(tmp_path / "catalog.json")}


def catalog(cfg, **kw):
    name = "duoauthproxy-6.7.0-src.tgz"
    e = {"provider": "duo", "version": "6.7.0", "file": name, "url": "https://dl.duosecurity.com/" + name,
         "size": len(BUILD), "sha256": hashlib.sha256(BUILD).hexdigest()}
    e.update(kw)
    with open(cfg["integration_catalog"], "w") as fh:
        json.dump({"format": 1, "serial": 1, "entries": [e]}, fh)


@pytest.fixture
def net(monkeypatch):
    calls = []

    def urlopen(req, timeout=None):
        calls.append(req.full_url)
        return FakeResponse(net.data, net.final or req.full_url)
    net.data, net.final = BUILD, None
    monkeypatch.setattr(f.urllib.request, "urlopen", urlopen)
    net.calls = calls
    return net


def test_listed_build_downloaded_and_checked(cfg, net):
    catalog(cfg)
    msg = f.fetch(cfg, "duo-6.7.0")
    assert net.calls == ["https://dl.duosecurity.com/duoauthproxy-6.7.0-src.tgz"]
    p = os.path.join(cfg["integration_dir"], "duoauthproxy-6.7.0-src.tgz")
    assert open(p, "rb").read() == BUILD and oct(os.stat(p).st_mode & 0o777) == "0o640"
    st = f.read_status(cfg["integration_dir"], "duo")
    assert st["state"] == "done" and st["listed"] is True and st["sha256"] == hashlib.sha256(BUILD).hexdigest()
    assert "downloaded" in msg


def test_unlisted_build_downloaded_and_reported(cfg, net):
    f.fetch(cfg, "duo-6.9.9")
    st = f.read_status(cfg["integration_dir"], "duo")
    assert st["state"] == "done" and st["listed"] is False and "not in the catalog" in st["message"]


def test_listed_build_that_does_not_match_is_dropped(cfg, net):
    catalog(cfg, sha256="0" * 64)
    with pytest.raises(f.FetchError):
        f.fetch(cfg, "duo-6.7.0")
    assert os.listdir(cfg["integration_dir"]) == ["fetch-duo.json"]
    st = f.read_status(cfg["integration_dir"], "duo")
    assert st["state"] == "failed" and "does not match the catalog" in st["message"]


def test_larger_than_listed_is_refused(cfg, net):
    catalog(cfg, size=10)
    with pytest.raises(f.FetchError):
        f.fetch(cfg, "duo-6.7.0")
    assert "larger than expected" in f.read_status(cfg["integration_dir"], "duo")["message"]


def test_redirect_away_from_the_vendor_is_refused(cfg, net):
    net.final = "https://evil.example.net/x.tgz"
    with pytest.raises(f.FetchError):
        f.fetch(cfg, "duo-6.7.0")
    assert not os.path.exists(os.path.join(cfg["integration_dir"], "duoauthproxy-6.7.0-src.tgz"))


def test_older_builds_are_removed(cfg, net):
    old = os.path.join(cfg["integration_dir"], "duoauthproxy-6.6.0-src.tgz")
    other = os.path.join(cfg["integration_dir"], "upload-note.txt")
    for p in (old, other):
        open(p, "w").close()
    f.fetch(cfg, "duo-6.7.0")
    assert not os.path.exists(old) and os.path.exists(other)


@pytest.mark.parametrize("instance", ["", "duo", "duo-6.7", "evil-1.2.3", "duo-6.7.0/../x", "duo-6.7.0\n"])
def test_bad_instance(cfg, net, instance):
    with pytest.raises(f.FetchError):
        f.fetch(cfg, instance)
    assert net.calls == []


def test_catalog_naming_another_file_refused(cfg, net):
    catalog(cfg, file="duoauthproxy-6.7.0-evil.tgz")
    with pytest.raises(f.FetchError):
        f.fetch(cfg, "duo-6.7.0")
    assert net.calls == []
