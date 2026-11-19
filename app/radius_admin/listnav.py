"""Going back to a list keeps its filters (SPEC section 24).

Each filtered list remembers the filters and page it was last shown with, so "Back to …",
Cancel and the redirect after a row action return to the same view instead of the
unfiltered first page. The state travels in a session cookie: the ui.session table has no
column for it and it is display state only. Nothing in the cookie is trusted: only the
argument names listed in LISTS are read, each value is cut to 100 characters, and the
values are only ever used to build the URL of the same list, where the view validates
them like any other query string.

Opening a list without arguments (the menu link) forgets its filters. The state is per
browser, not per tab: with the same list open in two tabs, "back" goes to the one shown last.
"""
import base64
import json

from flask import g, request, url_for

COOKIE = "__Host-radius_admin_lists"
MAX_VALUE = 100
MAX_COOKIE = 3000

# endpoint -> query arguments that make up its view
LISTS = {
    "sessions.index": ("q", "switch", "history", "page"),
    "sessions.actions": ("q", "switch", "action", "result", "page"),
    "logs.auth_log": ("user", "nas", "mac", "reply", "method", "since", "until", "page"),
    "clients.index": ("q",),
    "mab.index": ("q", "show", "page"),
    "mab.pending": ("q", "ignored"),
    "alerts.index": ("show",),
}


def _clean(state):
    out = {}
    if not isinstance(state, dict):
        return out
    for ep, names in LISTS.items():
        args = state.get(ep)
        if not isinstance(args, dict):
            continue
        kept = {k: args[k][:MAX_VALUE] for k in names if isinstance(args.get(k), str) and args[k]}
        if kept:
            out[ep] = kept
    return out


def _state():
    if "list_state" not in g:
        state = {}
        raw = request.cookies.get(COOKIE)
        if raw and len(raw) <= MAX_COOKIE + 200:
            try:
                state = _clean(json.loads(base64.urlsafe_b64decode(raw.encode())))
            except (ValueError, TypeError):
                state = {}
        g.list_state = state
    return g.list_state


def list_url(endpoint, **extra):
    """URL of a list with the filters and page it was last shown with."""
    args = dict(_state().get(endpoint, {}))
    args.update(extra)
    return url_for(endpoint, **args)


def _encode(state):
    return base64.urlsafe_b64encode(json.dumps(state, separators=(",", ":"), sort_keys=True).encode()).decode()


def install_listnav(app):
    app.jinja_env.globals["list_url"] = list_url

    @app.after_request
    def _remember(resp):
        ep = request.endpoint
        if ep == "auth.logout":
            if request.cookies.get(COOKIE):
                resp.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="Strict")
            return resp
        if ep not in LISTS or request.method != "GET" or resp.status_code != 200 or not g.get("user"):
            return resp
        old = _state()
        new = dict(old)
        args = {k: request.args.get(k, "").strip()[:MAX_VALUE] for k in LISTS[ep]}
        args = {k: v for k, v in args.items() if v}
        if args:
            new[ep] = args
        else:
            new.pop(ep, None)
        if new == old:
            return resp
        if not new:
            resp.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="Strict")
            return resp
        val = _encode(new)
        if len(val) > MAX_COOKIE:              # very long filters: keep this list only
            val = _encode({ep: new[ep]} if ep in new else {})
        resp.set_cookie(COOKIE, val, secure=True, httponly=True, samesite="Strict", path="/")
        return resp
