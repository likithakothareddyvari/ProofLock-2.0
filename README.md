# ProofLock 2.0
**Blockchain-Based Digital Evidence Protection System**  
YUKTHI 2026 · Blockchain & Cybersecurity

ProofLock 2.0 is a student prototype that demonstrates file integrity checking with SHA-256, a hash-linked audit trail, custody-event logging, and downloadable verification reports.

## Five main features
1. **File Tampering Detection:** Recomputes a file's SHA-256 hash and compares it with the registered hash.
2. **Blockchain-style Audit Trail:** Audit events link to the previous record hash; the app validates the chain.
3. **Evidence Verification Report:** Downloads a text report with hashes, integrity status and event history.
4. **Privacy Protection:** Evidence file bytes are not copied into audit records. The demo stores uploaded files locally and keeps metadata in SQLite. Do not upload sensitive real evidence.
5. **Chain-of-Custody Verification:** Records access/transfer/received/reviewed events with actor, recipient and notes.

## Important implementation note
This prototype uses a **local SQLite hash-linked audit log**, not a distributed blockchain. Describe it accurately in your demo. A production blockchain integration would require a network, identity/access controls, key management, and independent validation.

## Tech stack
- Python 3
- Flask
- SQLite
- SHA-256 (`hashlib`)
- HTML/CSS

## Run locally
1. Install Python 3.10+.
2. Open a terminal in this folder.
3. Create and activate a virtual environment (optional but recommended):
   - Windows: `py -m venv .venv` then `.venv\\Scripts\\activate`
   - macOS/Linux: `python3 -m venv .venv` then `source .venv/bin/activate`
4. Install packages: `pip install -r requirements.txt`
5. Start: `python app.py`
6. Open the local URL printed in the terminal, normally `http://127.0.0.1:5000`.

## Demo walkthrough
1. Upload a harmless sample PDF/TXT/image.
2. Show the Evidence Register and the SHA-256 hash.
3. Click **Verify file**; show the integrity success message.
4. Record a custody event such as TRANSFER or RECEIVED.
5. Download the verification report.
6. Open **Audit Trail** and show the hash-chain validation message.
7. Optionally, for a controlled test only, stop the app and alter a stored evidence file in the `evidence/` folder, then restart and verify it. Use a copy/sample file, not real evidence.

## Privacy and security limits
- This is a local educational prototype, not a forensic-grade evidence platform.
- Uploaded files are stored locally in `evidence/`; the audit log stores event details and hashes, not file bytes.
- The demo has no authentication/authorization, production-grade encryption, trusted timestamping, or distributed blockchain consensus.
- Do not expose it publicly or upload sensitive personal/legal evidence.
- Set a unique `PROOFLOCK_SECRET` environment variable before any non-demo use. Debug mode is enabled only for local development.

## Suggested repository structure
```text
ProofLock_2_0/
├── app.py
├── requirements.txt
├── README.md
├── templates/
│   ├── base.html
│   ├── index.html
│   └── audit.html
├── static/
│   └── style.css
└── evidence/
    └── .gitkeep
```

## Suggested 2–3 minute screen recording
- 0:00–0:15 — Introduce project and problem.
- 0:15–0:40 — Upload a harmless sample file and register it.
- 0:40–1:05 — Explain SHA-256 and click Verify.
- 1:05–1:30 — Record a custody event.
- 1:30–1:55 — Download/open the verification report.
- 1:55–2:20 — Show audit trail and hash-chain status.
- 2:20–2:40 — State prototype limitations honestly and explain future real blockchain integration.

## YUKTHI submission checklist
- [ ] Run the app locally and test each button.
- [ ] Add a screenshot of the running app to the repository README (optional but useful).
- [ ] Create a GitHub repository named `ProofLock-2.0`.
- [ ] Upload the source files and README.
- [ ] Copy the real repository URL into the submission form.
- [ ] Record the actual prototype screen; do not submit a fabricated demo.
