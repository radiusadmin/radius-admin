"""PostgreSQL access (psycopg2, parameterized queries only).

One connection per request, borrowed from a thread-safe pool, committed at
teardown when the request succeeded and rolled back otherwise.
"""
import threading

import psycopg2
import psycopg2.extras
import psycopg2.pool
from flask import current_app, g

_pools = {}
_pools_lock = threading.Lock()


def utc_dsn(dsn):
    """The DSN with the session time zone forced to UTC (added to any existing options).

    timestamptz values then come back in UTC whatever the server's time zone is, so
    dates and "... UTC" labels the app derives from them are right on every host."""
    params = psycopg2.extensions.parse_dsn(dsn)
    params["options"] = (params.get("options", "") + " -c timezone=UTC").strip()
    return psycopg2.extensions.make_dsn(**params)


def _pool(dsn, maxconn):
    with _pools_lock:
        pool = _pools.get(dsn)
        if pool is None:
            pool = psycopg2.pool.ThreadedConnectionPool(0, maxconn, utc_dsn(dsn))
            _pools[dsn] = pool
        return pool


def connect(dsn):
    """Standalone connection (CLI, monitor service)."""
    conn = psycopg2.connect(utc_dsn(dsn))
    conn.autocommit = False
    return conn


def get_db():
    if "db" not in g:
        cfg = current_app.config["RA"]
        conn = _pool(cfg["db_dsn"], cfg["db_pool_max"]).getconn()
        conn.autocommit = False
        g.db = conn
    return g.db


def close_db(exc=None):
    conn = g.pop("db", None)
    if conn is None:
        return
    cfg = current_app.config["RA"]
    pool = _pool(cfg["db_dsn"], cfg["db_pool_max"])
    broken = False
    try:
        if exc is None and not g.get("db_rollback"):
            conn.commit()
        else:
            conn.rollback()
    except psycopg2.Error:
        broken = True
        try:
            conn.rollback()
        except psycopg2.Error:
            pass
    pool.putconn(conn, close=broken or conn.closed != 0)


def close_pools():
    with _pools_lock:
        for pool in _pools.values():
            pool.closeall()
        _pools.clear()


def cursor(conn=None):
    return (conn or get_db()).cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def query(sql, params=(), conn=None):
    with cursor(conn) as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def query_one(sql, params=(), conn=None):
    with cursor(conn) as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def execute(sql, params=(), conn=None):
    with cursor(conn) as cur:
        cur.execute(sql, params)
        return cur.rowcount


def execute_returning(sql, params=(), conn=None):
    with cursor(conn) as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def commit():
    get_db().commit()


def query_one_optional(sql, params=(), conn=None):
    """query_one inside a savepoint: returns None instead of aborting the request's
    transaction when the query fails (e.g. a table that a later upgrade phase adds)."""
    c = conn or get_db()
    with c.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SAVEPOINT ra_optional")
        try:
            cur.execute(sql, params)
            row = cur.fetchone()
        except psycopg2.Error:
            cur.execute("ROLLBACK TO SAVEPOINT ra_optional")
            row = None
        cur.execute("RELEASE SAVEPOINT ra_optional")
        return row
