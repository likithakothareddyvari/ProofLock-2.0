import os, sqlite3, hashlib, json
from datetime import datetime, timezone
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from werkzeug.utils import secure_filename
from io import BytesIO

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "prooflock.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "evidence")
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "txt", "docx", "mp4"}
MAX_BYTES = 20 * 1024 * 1024

app = Flask(__name__)
app.secret_key = os.environ.get("PROOFLOCK_SECRET", "change-this-demo-secret")
app.config["MAX_CONTENT_LENGTH"] = MAX_BYTES

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()

def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    with connect() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_name TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            created_at TEXT NOT NULL,
            description TEXT DEFAULT ''
        )""")
        con.execute("""CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            evidence_id INTEGER,
            event TEXT NOT NULL,
            actor TEXT NOT NULL,
            details TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            record_hash TEXT NOT NULL
        )""")

def append_audit(evidence_id, event, actor, details):
    with connect() as con:
        previous = con.execute("SELECT record_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev_hash = previous["record_hash"] if previous else "GENESIS"
        timestamp = now()
        payload = json.dumps({
            "evidence_id": evidence_id, "event": event, "actor": actor,
            "details": details, "timestamp": timestamp, "previous_hash": prev_hash
        }, sort_keys=True, separators=(",", ":"))
        record_hash = sha256_bytes(payload.encode("utf-8"))
        con.execute("""INSERT INTO audit
            (evidence_id,event,actor,details,timestamp,previous_hash,record_hash)
            VALUES (?,?,?,?,?,?,?)""",
            (evidence_id,event,actor,details,timestamp,prev_hash,record_hash))

def verify_audit_chain():
    with connect() as con:
        rows = con.execute("SELECT * FROM audit ORDER BY id").fetchall()
    expected_prev = "GENESIS"
    for row in rows:
        if row["previous_hash"] != expected_prev:
            return False, f"Previous-hash mismatch at audit record #{row['id']}"
        payload = json.dumps({
            "evidence_id": row["evidence_id"], "event": row["event"],
            "actor": row["actor"], "details": row["details"],
            "timestamp": row["timestamp"], "previous_hash": row["previous_hash"]
        }, sort_keys=True, separators=(",", ":"))
        if sha256_bytes(payload.encode("utf-8")) != row["record_hash"]:
            return False, f"Record hash mismatch at audit record #{row['id']}"
        expected_prev = row["record_hash"]
    return True, f"All {len(rows)} audit record(s) passed the hash-chain check."

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def index():
    with connect() as con:
        evidence = con.execute("SELECT * FROM evidence ORDER BY id DESC").fetchall()
        audit = con.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 8").fetchall()
    chain_ok, chain_message = verify_audit_chain()
    return render_template("index.html", evidence=evidence, audit=audit,
                           chain_ok=chain_ok, chain_message=chain_message)

@app.route("/upload", methods=["POST"])
def upload():
    file = request.files.get("file")
    description = request.form.get("description", "").strip()[:300]
    actor = request.form.get("actor", "Demo User").strip()[:80] or "Demo User"
    if not file or not file.filename:
        flash("Choose a file first.", "error")
        return redirect(url_for("index"))
    if not allowed_file(file.filename):
        flash("File type not supported. Use PDF, PNG, JPG, TXT, DOCX or MP4.", "error")
        return redirect(url_for("index"))
    data = file.read()
    if not data:
        flash("The selected file is empty.", "error")
        return redirect(url_for("index"))
    original_name = secure_filename(file.filename) or "evidence_file"
    digest = sha256_bytes(data)
    stored_name = f"{digest[:16]}_{original_name}"
    path = os.path.join(UPLOAD_DIR, stored_name)
    with open(path, "wb") as out:
        out.write(data)
    with connect() as con:
        cur = con.execute("""INSERT INTO evidence
            (original_name,stored_name,sha256,created_at,description)
            VALUES (?,?,?,?,?)""", (original_name, stored_name, digest, now(), description))
        evidence_id = cur.lastrowid
    append_audit(evidence_id, "EVIDENCE_REGISTERED", actor,
                 f"SHA-256 recorded; original file stored locally; description={description or 'none'}")
    flash(f"Evidence registered successfully. Evidence ID: {evidence_id}", "success")
    return redirect(url_for("index"))

@app.route("/verify/<int:evidence_id>", methods=["POST"])
def verify(evidence_id):
    actor = request.form.get("actor", "Demo User").strip()[:80] or "Demo User"
    with connect() as con:
        row = con.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if not row:
        abort(404)
    path = os.path.join(UPLOAD_DIR, row["stored_name"])
    if not os.path.isfile(path):
        result = "FILE_MISSING"
        message = "Stored evidence file is missing."
    else:
        with open(path, "rb") as f:
            current_hash = sha256_bytes(f.read())
        if current_hash == row["sha256"]:
            result = "INTEGRITY_VERIFIED"
            message = "The current file hash matches the registered SHA-256 hash."
        else:
            result = "HASH_MISMATCH"
            message = "The current file hash does not match the registered hash."
    append_audit(evidence_id, "EVIDENCE_VERIFIED", actor, f"{result}: {message}")
    flash(f"{result}: {message}", "success" if result == "INTEGRITY_VERIFIED" else "error")
    return redirect(url_for("index"))

@app.route("/custody/<int:evidence_id>", methods=["POST"])
def custody(evidence_id):
    actor = request.form.get("actor", "Demo User").strip()[:80] or "Demo User"
    recipient = request.form.get("recipient", "").strip()[:80]
    action = request.form.get("action", "TRANSFER").strip().upper()
    note = request.form.get("note", "").strip()[:250]
    with connect() as con:
        row = con.execute("SELECT id FROM evidence WHERE id=?", (evidence_id,)).fetchone()
    if not row:
        abort(404)
    details = f"action={action}; recipient={recipient or 'not specified'}; note={note or 'none'}"
    append_audit(evidence_id, "CUSTODY_EVENT", actor, details)
    flash("Chain-of-custody event recorded.", "success")
    return redirect(url_for("index"))

@app.route("/report/<int:evidence_id>")
def report(evidence_id):
    with connect() as con:
        item = con.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        events = con.execute("SELECT * FROM audit WHERE evidence_id=? ORDER BY id", (evidence_id,)).fetchall()
    if not item:
        abort(404)
    path = os.path.join(UPLOAD_DIR, item["stored_name"])
    current_hash = None
    if os.path.isfile(path):
        with open(path, "rb") as f:
            current_hash = sha256_bytes(f.read())
    integrity = "VERIFIED" if current_hash == item["sha256"] else "MISMATCH OR FILE MISSING"
    chain_ok, chain_message = verify_audit_chain()
    lines = [
        "PROOFLOCK 2.0 — EVIDENCE VERIFICATION REPORT",
        "=" * 52,
        f"Generated (UTC): {now()}",
        f"Evidence ID: {item['id']}",
        f"Original filename: {item['original_name']}",
        f"Registered at (UTC): {item['created_at']}",
        f"Description: {item['description'] or 'None'}",
        f"Registered SHA-256: {item['sha256']}",
        f"Current SHA-256: {current_hash or 'FILE MISSING'}",
        f"File integrity status: {integrity}",
        f"Audit hash-chain status: {'VALID' if chain_ok else 'INVALID'}",
        f"Audit chain detail: {chain_message}",
        "",
        "EVIDENCE EVENTS"
    ]
    for e in events:
        lines.append(f"#{e['id']} | {e['timestamp']} | {e['event']} | actor={e['actor']} | {e['details']}")
    lines += ["", "DEMO LIMITATION: This prototype uses a local SQLite hash-linked audit log, not a public or distributed blockchain.",
              "Privacy note: file bytes are not placed in audit records; this demo stores the uploaded file locally."]
    content = "\n".join(lines).encode("utf-8")
    return send_file(BytesIO(content), mimetype="text/plain",
                     as_attachment=True, download_name=f"prooflock_report_{evidence_id}.txt")

@app.route("/audit")
def audit_page():
    with connect() as con:
        rows = con.execute("SELECT * FROM audit ORDER BY id DESC").fetchall()
    chain_ok, chain_message = verify_audit_chain()
    return render_template("audit.html", audit=rows, chain_ok=chain_ok, chain_message=chain_message)

@app.errorhandler(413)
def too_large(_):
    flash("File is too large. Maximum allowed size is 20 MB.", "error")
    return redirect(url_for("index"))

init_db()

if __name__ == "__main__":
    app.run(debug=True)
