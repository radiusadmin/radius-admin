"""Blueprints and shared view helpers."""
from flask import g, request

from .. import audit
from ..security import client_ip


def ev(action, success=True, object_type=None, object_id=None, detail=None, actor=None):
    """Audit an event with actor / IP taken from the request context."""
    if actor is None and g.get("user"):
        actor = g.user["username"]
    return audit.write(action, success=success, actor=actor, actor_ip=client_ip(),
                       object_type=object_type, object_id=object_id, detail=detail)


def form_str(name, default="", maxlen=10000):
    v = request.form.get(name, default)
    if v is None:
        return default
    return v.strip()[:maxlen]


def form_bool(name):
    return request.form.get(name) in ("1", "on", "true", "yes")


def page_args(default_size=50, max_size=200):
    try:
        page = max(1, int(request.args.get("page", 1)))
    except ValueError:
        page = 1
    return page, default_size
