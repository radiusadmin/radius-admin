"""Certificates (SPEC section 30): the 802.1X server certificate, the client certificate CA, the
portal's HTTPS certificate and OCSP for EAP-TLS. Upload a certificate and key (PEM or PKCS#12),
or make a key and request here and upload the issued certificate later. Changes are staged and
reach the server with Review and apply."""
import datetime

from flask import Blueprint, Response, abort, current_app, redirect, render_template, request, url_for

from .. import certs, helper_client
from ..flashing import flash
from ..security import cfg, login_required, role_required, stepup_required
from ..services import get_settings, set_setting
from . import ev, form_str

bp = Blueprint("certificates", __name__, url_prefix="/certificates")

MAX_UPLOAD = 128 * 1024


def _helper_status():
    try:
        r = helper_client.call(cfg()["helper_socket"], "cert_status", timeout=cfg()["helper_timeout"])
    except helper_client.HelperError as e:
        return {"ok": False, "message": str(e)}
    return r if isinstance(r, dict) else {"ok": False, "message": "bad answer"}


def _kind(kind, server_only=False):
    if kind not in (certs.SERVER_KINDS if server_only else certs.KINDS):
        abort(404)
    return kind


def _file_or_text(field, text_field=None):
    """Bytes of an uploaded file, else the pasted text (both optional)."""
    f = request.files.get(field)
    if f is not None and f.filename:
        data = f.stream.read(MAX_UPLOAD + 1)
        if len(data) > MAX_UPLOAD:
            raise certs.CertError("the file is too large")
        return data
    if text_field:
        t = request.form.get(text_field, "")
        if len(t) > MAX_UPLOAD:
            raise certs.CertError("the text is too large")
        return t.encode() if t.strip() else None
    return None


def _portal_name(status):
    return (status.get("portal_server_name") if status.get("ok") else None) or cfg().get("server_name") or None


def _installed_sha(status, kind):
    items = status.get(kind) if status.get("ok") else None
    return items[0].get("sha256") if items and isinstance(items[0], dict) else None


def _managed_view(rows):
    out = {}
    for kind in certs.KINDS:
        r = rows.get(kind)
        v = {"row": r, "certs": [], "csr": None, "error": None}
        if r and r["cert_pem"]:
            try:
                v["certs"] = [certs.describe(c) for c in certs.load_certs(r["cert_pem"])]
            except certs.CertError as e:
                v["error"] = str(e)
        if r and r["csr_pem"]:
            try:
                v["csr"] = certs.csr_info(r["csr_pem"])
            except ValueError:
                v["error"] = "the stored request cannot be read"
        out[kind] = v
    return out


@bp.route("/")
@login_required
def index():
    status = _helper_status()
    rows = certs.rows()
    managed = _managed_view(rows)
    for kind in certs.KINDS:
        m = managed[kind]
        m["applied"] = bool(m["certs"]) and m["certs"][0]["sha256"].replace(":", "").lower() == \
            (_installed_sha(status, kind) or "").replace(":", "").lower()
    mode, url = certs.ocsp_setting(get_settings())
    for kind in certs.KINDS:
        for item in (status.get(kind) or []) if status.get("ok") else []:
            _days_left(item)
    return render_template("certificates/index.html", status=status, managed=managed, labels=certs.LABELS,
                           key_types=certs.KEY_TYPES, ocsp_mode=mode, ocsp_url=url,
                           portal_name=_portal_name(status))


def _days_left(item):
    """Installed certificates come from the helper with openssl's dates ('Nov 20 12:00:00 2027 GMT')."""
    if not isinstance(item, dict) or not item.get("not_after"):
        return
    try:
        na = datetime.datetime.strptime(item["not_after"], "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=datetime.timezone.utc)
    except ValueError:
        return
    item["days_left"] = (na - datetime.datetime.now(datetime.timezone.utc)).days
    item["not_after"] = na


@bp.route("/<kind>/upload", methods=["POST"])
@role_required("admin")
@stepup_required
def upload(kind):
    kind = _kind(kind)
    status = _helper_status()
    password = request.form.get("password", "")[:200]
    try:
        if kind == "client_ca":
            data = _file_or_text("cert_file", "cert_text")
            if not data:
                raise certs.CertError("choose the CA certificate file or paste it")
            pem = certs.check_ca_bundle(certs.load_certs(data, "CA bundle"))
            certs.save_cert(kind, pem, None, current_app.config["RA_DATA_KEY"], _actor())
        else:
            p12 = _file_or_text("p12_file")
            if p12:
                chain, key = certs.load_pkcs12(p12, password)
            else:
                data = _file_or_text("cert_file", "cert_text")
                kdata = _file_or_text("key_file", "key_text")
                if not data or not kdata:
                    raise certs.CertError("give the certificate and its private key (or a PKCS#12 file)")
                chain = certs.load_certs(data)
                extra = _file_or_text("chain_file", "chain_text")
                if extra:
                    chain += certs.load_certs(extra, "chain")
                key = certs.load_key(kdata, password or None)
            cert_pem, key_pem = certs.check_server(
                chain, key, server_name=_portal_name(status) if kind == "portal_server" else None)
            certs.save_cert(kind, cert_pem, key_pem, current_app.config["RA_DATA_KEY"], _actor())
    except certs.CertError as e:
        ev("certificate.upload", success=False, object_type="certificate", object_id=kind,
           detail={"reason": str(e)[:300]})
        flash("%s not saved: %s." % (certs.LABELS[kind], e), "error")
        return redirect(url_for("certificates.index") + "#" + kind)
    first = certs.load_certs(cert_pem if kind != "client_ca" else pem)
    d = certs.describe(first[0])
    ev("certificate.upload", object_type="certificate", object_id=kind,
       detail={"subject": d["subject"], "issuer": d["issuer"], "sha256": d["sha256"],
               "not_after": d["not_after"].strftime("%Y-%m-%d"), "count": len(first)})
    flash("%s saved: %s. Review and apply to install it." % (certs.LABELS[kind], d["subject"]), "success")
    return redirect(url_for("certificates.index") + "#" + kind)


@bp.route("/<kind>/csr", methods=["POST"])
@role_required("admin")
@stepup_required
def make_csr(kind):
    kind = _kind(kind, server_only=True)
    status = _helper_status()
    cn = form_str("common_name", maxlen=253) or (_portal_name(status) or "")
    names = [n for n in form_str("dns_names", maxlen=4000).replace(",", " ").split() if n]
    key_type = form_str("key_type", maxlen=20) or "ecdsa-p384"
    try:
        if kind == "portal_server" and _portal_name(status) and _portal_name(status).lower() not in \
                [n.lower() for n in [cn] + names]:
            names.append(_portal_name(status))
        csr_pem, key_pem = certs.generate_csr(cn, names, key_type)
    except certs.CertError as e:
        flash("No request made: %s." % e, "error")
        return redirect(url_for("certificates.index") + "#" + kind)
    certs.save_csr(kind, csr_pem, key_pem, current_app.config["RA_DATA_KEY"], _actor())
    info = certs.csr_info(csr_pem)
    ev("certificate.csr", object_type="certificate", object_id=kind,
       detail={"subject": info["subject"], "san": info["san"], "key_type": info["key"]})
    flash("Key and certificate request made for %s. Download the request, have your CA issue the certificate, "
          "then upload it here." % info["subject"], "success")
    return redirect(url_for("certificates.index") + "#" + kind)


@bp.route("/<kind>/request.csr")
@role_required("admin")
def download_csr(kind):
    kind = _kind(kind, server_only=True)
    r = certs.rows().get(kind)
    if not r or not r["csr_pem"]:
        abort(404)
    return Response(r["csr_pem"], mimetype="application/pkcs10",
                    headers={"Content-Disposition": "attachment; filename=%s.csr" % kind.replace("_", "-")})


@bp.route("/<kind>/issued", methods=["POST"])
@role_required("admin")
@stepup_required
def issued(kind):
    kind = _kind(kind, server_only=True)
    r = certs.rows().get(kind)
    if not r or not r["csr_pem"]:
        flash("There is no pending request for the %s." % certs.LABELS[kind].lower(), "error")
        return redirect(url_for("certificates.index") + "#" + kind)
    status = _helper_status()
    dk = current_app.config["RA_DATA_KEY"]
    try:
        data = _file_or_text("cert_file", "cert_text")
        if not data:
            raise certs.CertError("choose the issued certificate file or paste it")
        chain = certs.load_certs(data)
        extra = _file_or_text("chain_file", "chain_text")
        if extra:
            chain += certs.load_certs(extra, "chain")
        key = certs.csr_key(r, dk)
        cert_pem, key_pem = certs.check_server(
            chain, key, server_name=_portal_name(status) if kind == "portal_server" else None,
            what="issued certificate")
    except certs.CertError as e:
        flash("Certificate not saved: %s." % e, "error")
        return redirect(url_for("certificates.index") + "#" + kind)
    certs.complete_csr(kind, cert_pem, key_pem, dk, _actor())
    d = certs.describe(chain[0])
    ev("certificate.issued", object_type="certificate", object_id=kind,
       detail={"subject": d["subject"], "issuer": d["issuer"], "sha256": d["sha256"],
               "not_after": d["not_after"].strftime("%Y-%m-%d")})
    flash("%s saved: %s. Review and apply to install it." % (certs.LABELS[kind], d["subject"]), "success")
    return redirect(url_for("certificates.index") + "#" + kind)


@bp.route("/<kind>/forget", methods=["POST"])
@role_required("admin")
@stepup_required
def forget(kind):
    kind = _kind(kind)
    what = "csr" if request.form.get("what") == "csr" else "all"
    certs.forget(kind, what)
    ev("certificate.forget", object_type="certificate", object_id=kind, detail={"what": what})
    flash("Pending request discarded." if what == "csr" else
          "The portal no longer manages the %s; the installed one stays as it is." % certs.LABELS[kind].lower(),
          "success")
    return redirect(url_for("certificates.index") + "#" + kind)


@bp.route("/ocsp", methods=["POST"])
@role_required("admin")
@stepup_required
def ocsp():
    mode = form_str("mode", maxlen=10)
    url = form_str("url", maxlen=300)
    if mode not in certs.OCSP_MODES:
        abort(400)
    if mode == "on" and not certs.OCSP_URL_RE.match(url):
        flash("OCSP not changed: give the responder as an http(s) URL.", "error")
        return redirect(url_for("certificates.index") + "#eap_ocsp")
    before = certs.ocsp_setting(get_settings())
    set_setting("eap_ocsp", mode)
    set_setting("eap_ocsp_url", url if mode == "on" else "")
    ev("certificate.ocsp", object_type="setting", object_id="eap_ocsp",
       detail={"from": {"mode": before[0], "url": before[1]}, "to": {"mode": mode, "url": url if mode == "on" else ""}})
    flash("OCSP setting saved. Review and apply to install it." if mode != "keep" else
          "OCSP is left as it is installed.", "success")
    return redirect(url_for("certificates.index") + "#eap_ocsp")


def _actor():
    from flask import g
    return g.user["username"]
