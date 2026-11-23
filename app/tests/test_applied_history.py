"""The app's copy of applied files (applied/ and applied/history/<backup_id>/) holds rendered
provider files, the Duo secret key and managed private keys among them: it keeps only as many
sets as the helper keeps backups, and seals the provider files with the data key."""
import os

from radius_admin import services
from radius_admin.crypto import DataKey

SKEY = "S" * 40
DUO = "; radius-admin\n[radius_server_auto]\nskey=%s\n" % SKEY
CERTS = '{"eap_server": {"cert": "-----BEGIN CERTIFICATE-----", "key": "-----BEGIN PRIVATE KEY-----TESTONLY"}}\n'


def _key():
    return DataKey(os.urandom(32))


def _ids(n):
    return ["202611%02dT%02d%02d00Z" % (1 + i // 60, (i // 60) % 24, i % 60) for i in range(n)]


def _on_disk(base):
    """Every provider file below applied/, as stored."""
    out = {}
    for root, _dirs, files in os.walk(services.applied_dir(base)):
        for f in files:
            if f in services.PROVIDER_FILES:
                with open(os.path.join(root, f), encoding="utf-8") as fh:
                    out[os.path.join(root, f)] = fh.read()
    return out


def test_history_is_pruned_to_the_helpers_backups(tmp_path):
    base, key = str(tmp_path), _key()
    ids = _ids(services.APPLIED_HISTORY_KEEP + 5)
    for n, bid in enumerate(ids):
        services.save_applied("policy %d\n" % n, "clients %d\n" % n, base=base, backup_id=bid,
                              providers={"provider-duo": DUO + "; %d\n" % n}, datakey=key)
    hist = os.path.join(services.applied_dir(base), "history")
    os.makedirs(os.path.join(hist, "not-a-backup"))
    services.save_applied("policy x\n", "clients x\n", base=base, backup_id="20261201T000000Z", providers={},
                          datakey=key)
    kept = sorted(n for n in os.listdir(hist) if n != "not-a-backup")
    assert len(kept) == services.APPLIED_HISTORY_KEEP
    assert kept[-1] == "20261201T000000Z" and ids[0] not in kept and ids[5] not in kept and ids[6] in kept
    # the oldest copies of the Duo configuration are gone with them
    assert not os.path.exists(os.path.join(hist, ids[0], "provider-duo"))
    assert os.path.isdir(os.path.join(hist, "not-a-backup"))       # only backup ids are touched


def test_rollback_bookkeeping_prunes_too(tmp_path):
    base, key = str(tmp_path), _key()
    ids = _ids(services.APPLIED_HISTORY_KEEP + 2)
    for n, bid in enumerate(ids):
        services.save_applied("policy %d\n" % n, "clients %d\n" % n, base=base, backup_id=bid, providers={},
                              datakey=key)
    hist = os.path.join(services.applied_dir(base), "history")
    assert len(os.listdir(hist)) == services.APPLIED_HISTORY_KEEP
    assert services.restore_applied_from_history(ids[-1], base=base, new_backup_id="20261201T000000Z",
                                                 datakey=key) \
        == ("policy %d\n" % (len(ids) - 2), "clients %d\n" % (len(ids) - 2))
    assert len(os.listdir(hist)) == services.APPLIED_HISTORY_KEEP and "20261201T000000Z" in os.listdir(hist)


def test_provider_copies_are_sealed(tmp_path):
    base, key = str(tmp_path), _key()
    files = {"provider-duo": DUO, "certificates": CERTS}
    services.save_applied("p1\n", "c1\n", base=base, backup_id="20261101T000000Z", providers=files, datakey=key)
    services.save_applied("p2\n", "c2\n", base=base, backup_id="20261102T000000Z", providers={}, datakey=key)
    disk = _on_disk(base)
    assert len(disk) == 2 and all("history" in p for p in disk)     # applied/ now has none
    for text in disk.values():
        assert text.startswith("ra-sealed-v1:") and SKEY not in text and "PRIVATE KEY" not in text
    # read back through the data key, and restored by a rollback
    assert services.restore_applied_from_history("20261102T000000Z", base=base, datakey=key) == ("p1\n", "c1\n")
    assert services.read_applied(base, key)["providers"] == files
    disk = _on_disk(base)
    assert disk and all(SKEY not in t and "PRIVATE KEY" not in t for t in disk.values())
    # the providers hash the apply log records is the hash of the real files
    assert services.providers_sha256(services.read_applied(base, key)["providers"]) == services.providers_sha256(files)


def test_plain_copies_of_earlier_versions_are_sealed(tmp_path):
    base, key = str(tmp_path), _key()
    d = services.applied_dir(base)
    os.makedirs(os.path.join(d, "history", "20261101T000000Z"))
    for x in (d, os.path.join(d, "history", "20261101T000000Z")):
        for name in ("policy", "clients"):
            with open(os.path.join(x, name), "w") as fh:
                fh.write(name + "\n")
        with open(os.path.join(x, "provider-duo"), "w") as fh:
            fh.write(DUO)
    assert services.read_applied(base, key)["providers"] == {"provider-duo": DUO}    # still readable
    services.save_applied("p2\n", "c2\n", base=base, backup_id="20261102T000000Z",
                          providers={"provider-duo": DUO}, datakey=key)
    disk = _on_disk(base)
    assert len(disk) == 3 and all(SKEY not in t for t in disk.values())
    assert services.read_applied(os.path.join(base), key)["providers"] == {"provider-duo": DUO}


CLIENT_SECRET = "TestOnlyClientSecret0123456789"
CLIENTS = 'client sw1 {\n\tipaddr = 192.0.2.10\n\tsecret = "%s"\n}\n' % CLIENT_SECRET


def _clients_on_disk(base):
    out = {}
    for root, _dirs, files in os.walk(services.applied_dir(base)):
        if "clients" in files:
            with open(os.path.join(root, "clients"), encoding="utf-8") as fh:
                out[root] = fh.read()
    return out


def test_clients_copies_are_sealed(tmp_path):
    """The clients file holds every RADIUS shared secret: sealed like the provider files."""
    base, key = str(tmp_path), _key()
    services.save_applied("p1\n", CLIENTS, base=base, providers={}, datakey=key)
    services.save_applied("p2\n", CLIENTS + "# 2\n", base=base, backup_id="20261102T000000Z", providers={},
                          datakey=key)
    disk = _clients_on_disk(base)
    assert len(disk) == 2 and all(t.startswith("ra-sealed-v1:") and CLIENT_SECRET not in t for t in disk.values())
    assert services.read_applied(base, key)["clients"] == CLIENTS + "# 2\n"
    assert services.restore_applied_from_history("20261102T000000Z", base=base, new_backup_id="20261103T000000Z",
                                                 datakey=key) == ("p1\n", CLIENTS)
    assert services.read_applied(base, key)["clients"] == CLIENTS
    disk = _clients_on_disk(base)
    assert len(disk) == 3 and all(CLIENT_SECRET not in t for t in disk.values())


def test_plain_clients_copies_are_sealed_and_a_replaced_key_drops_them(tmp_path):
    base, key = str(tmp_path), _key()
    d = services.applied_dir(base)
    os.makedirs(os.path.join(d, "history", "20261101T000000Z"))
    for x in (d, os.path.join(d, "history", "20261101T000000Z")):
        with open(os.path.join(x, "policy"), "w") as fh:
            fh.write("policy\n")
        with open(os.path.join(x, "clients"), "w") as fh:
            fh.write(CLIENTS)
    assert services.read_applied(base, key)["clients"] == CLIENTS                     # still readable
    services.save_applied("p2\n", CLIENTS, base=base, backup_id="20261102T000000Z", providers={}, datakey=key)
    assert all(CLIENT_SECRET not in t for t in _clients_on_disk(base).values())
    # with another data key the copy counts as missing, and a rollback to it finds no archived set
    other = _key()
    assert services.read_applied(base, other)["clients"] is None
    assert services.restore_applied_from_history("20261101T000000Z", base=base, datakey=other) is None


def test_a_replaced_data_key_makes_sealed_copies_count_as_missing(tmp_path):
    base = str(tmp_path)
    services.save_applied("p\n", "c\n", base=base, providers={"provider-duo": DUO}, datakey=_key())
    assert services.read_applied(base, _key())["providers"] == {}
