"""Numbered pages for long lists (authentication log, audit log, sessions).

A list view counts the matching rows (capped, so a huge table never costs a full
count), builds a Pager from the requested page and reads one page at pager.offset.
The pager macro in _macros.html renders "Previous 1 … 4 5 [6] 7 8 … 40 Next".
"""
from flask import request

MAX_PAGE = 10000


def requested_page():
    """The ?page= argument as 1..MAX_PAGE; anything unusable is page 1."""
    try:
        return max(1, min(MAX_PAGE, int(request.args.get("page", 1))))
    except (TypeError, ValueError):
        return 1


def count(db, from_where, params, per_page):
    """Rows matching `FROM ... WHERE ...`, counted up to MAX_PAGE pages (+1 to tell it was capped)."""
    cap = MAX_PAGE * per_page
    row = db.query_one("SELECT count(*) AS n FROM (SELECT 1 " + from_where + " LIMIT %s) t",
                       list(params) + [cap + 1])
    return row["n"]


class Pager:
    """One page of `total` rows, `per_page` at a time. A page past the end shows the last page."""

    def __init__(self, page, per_page, total):
        cap = MAX_PAGE * per_page
        self.capped = total > cap
        self.total = min(total, cap)
        self.per_page = per_page
        self.pages = max(1, -(-self.total // per_page))
        self.page = max(1, min(page, self.pages))
        self.offset = (self.page - 1) * per_page

    @property
    def first(self):
        """Number of the first row on this page (1-based; 0 when there are none)."""
        return self.offset + 1 if self.total else 0

    @property
    def last(self):
        return min(self.offset + self.per_page, self.total)

    @property
    def has_prev(self):
        return self.page > 1

    @property
    def has_next(self):
        return self.page < self.pages

    def numbers(self, around=2):
        """Page numbers to link, None where a run is left out: always the first and last
        page and `around` pages each side of the current one. A gap of a single page shows
        that page instead of an ellipsis."""
        want = {1, self.pages} | set(range(self.page - around, self.page + around + 1))
        shown = sorted(n for n in want if 1 <= n <= self.pages)
        out, prev = [], 0
        for n in shown:
            if n - prev == 2:
                out.append(prev + 1)
            elif n - prev > 2:
                out.append(None)
            out.append(n)
            prev = n
        return out
