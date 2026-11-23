"""The app's copy of applied files (applied/history/<backup_id>/) holds rendered provider files,
the Duo secret key among them: it keeps only as many sets as the helper keeps backups."""
import os

from radius_admin import services


def _ids(n):
    return ["202611%02dT%02d%02d00Z" % (1 + i // 60, (i // 60) % 24, i % 60) for i in range(n)]


def test_history_is_pruned_to_the_helpers_backups(tmp_path):
    base = str(tmp_path)
    ids = _ids(services.APPLIED_HISTORY_KEEP + 5)
    for n, bid in enumerate(ids):
        services.save_applied("policy %d\n" % n, "clients %d\n" % n, base=base, backup_id=bid,
                              providers={"provider-duo": "; radius-admin\nskey=%040d\n" % n})
    hist = os.path.join(services.applied_dir(base), "history")
    os.makedirs(os.path.join(hist, "not-a-backup"))
    services.save_applied("policy x\n", "clients x\n", base=base, backup_id="20261201T000000Z", providers={})
    kept = sorted(n for n in os.listdir(hist) if n != "not-a-backup")
    assert len(kept) == services.APPLIED_HISTORY_KEEP
    assert kept[-1] == "20261201T000000Z" and ids[0] not in kept and ids[5] not in kept and ids[6] in kept
    # the oldest copies of the Duo configuration are gone with them
    assert not os.path.exists(os.path.join(hist, ids[0], "provider-duo"))
    assert os.path.isdir(os.path.join(hist, "not-a-backup"))       # only backup ids are touched


def test_rollback_bookkeeping_prunes_too(tmp_path):
    base = str(tmp_path)
    ids = _ids(services.APPLIED_HISTORY_KEEP + 2)
    for n, bid in enumerate(ids):
        services.save_applied("policy %d\n" % n, "clients %d\n" % n, base=base, backup_id=bid, providers={})
    hist = os.path.join(services.applied_dir(base), "history")
    assert len(os.listdir(hist)) == services.APPLIED_HISTORY_KEEP
    assert services.restore_applied_from_history(ids[-1], base=base, new_backup_id="20261201T000000Z") \
        == ("policy %d\n" % (len(ids) - 2), "clients %d\n" % (len(ids) - 2))
    assert len(os.listdir(hist)) == services.APPLIED_HISTORY_KEEP and "20261201T000000Z" in os.listdir(hist)
