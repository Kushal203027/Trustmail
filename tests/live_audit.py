"""
TrustMail: Standalone Live Server Audit Runner.
Boots the server process, runs all 7 demonstration workflows over live HTTP sockets,
and asserts status codes, response payloads, and database persistence.
"""

import subprocess
import time
import httpx
import sys
from pathlib import Path

def main():
    print("==================================================")
    print(" TRUSTMAIL: LIVE END-TO-END SERVER AUDIT RUNNER   ")
    print("==================================================")

    # 1. Start uvicorn server in subprocess
    proc = subprocess.Popen([
        sys.executable, "-m", "uvicorn", "main:app",
        "--host", "127.0.0.1", "--port", "8000"
    ])

    # 2. Wait for server readiness
    server_ready = False
    for _ in range(25):
        time.sleep(0.4)
        try:
            r = httpx.get("http://127.0.0.1:8000", timeout=2.0)
            if r.status_code == 200:
                server_ready = True
                break
        except Exception:
            pass

    if not server_ready:
        print("[FAIL] Server failed to start or bind within timeout.")
        proc.terminate()
        sys.exit(1)

    print("[PASS] Server successfully bound to http://127.0.0.1:8000")
    client = httpx.Client(base_url="http://127.0.0.1:8000", timeout=5.0)

    try:
        # Check 1: Dashboard HTML and Static Assets
        r_root = client.get("/")
        r_css = client.get("/static/styles.css")
        r_js = client.get("/static/app.js")
        assert r_root.status_code == 200, f"Dashboard returned {r_root.status_code}"
        assert r_css.status_code == 200, f"CSS returned {r_css.status_code}"
        assert r_js.status_code == 200, f"JS returned {r_js.status_code}"
        print(f"[PASS] Workflow 0 (Frontend): Dashboard & Static Assets loaded (HTTP 200)")

        # Check 2: Synthetic Suspicious Email (Display Name Spoof + Wire Urgency)
        suspicious_email = (
            "From: \"CFO Sarah Connor <sarah@acme.com>\" <attacker@scam-mail.org>\r\n"
            "To: accounts@acme.com\r\n"
            "Subject: URGENT: Wire Transfer Routing Change\r\n"
            "Date: Mon, 19 Oct 2026 09:30:00 +0000\r\n"
            "\r\n"
            "Please execute an immediate wire transfer within 24 hours to our new bank routing."
        )
        r_susp = client.post("/api/analyze", json={"raw_email": suspicious_email, "retain_evidence": True})
        assert r_susp.status_code == 200
        susp_data = r_susp.json()
        assert susp_data["threat_assessment"]["level"] in {"HIGH", "CRITICAL"}
        assert susp_data["human_review_required"] is True
        assert susp_data["identity_assurance"]["level"] == "T-IAL 0"
        assert susp_data["message_authenticity"]["level"] == "MAL 1"
        assert susp_data["sender_trust"]["level"] == "STI 0"
        susp_id = susp_data["incident_id"]
        print(f"[PASS] Workflow 1: Suspicious email evaluated -> TSR: {susp_data['threat_assessment']['level']}, Review Mandated: {susp_data['human_review_required']}")

        # Check 3: Synthetic Legitimate Email
        legit_email = (
            "From: \"Tech Weekly\" <newsletter@technews.org>\r\n"
            "To: user@acme.com\r\n"
            "Subject: Weekly Open Source Security Digest\r\n"
            "Date: Mon, 19 Oct 2026 10:00:00 +0000\r\n"
            "\r\n"
            "Here is your weekly technology and cybersecurity roundup."
        )
        r_legit = client.post("/api/analyze", json={"raw_email": legit_email, "retain_evidence": False})
        assert r_legit.status_code == 200
        legit_data = r_legit.json()
        assert legit_data["threat_assessment"]["level"] == "LOW"
        assert legit_data["human_review_required"] is False
        assert legit_data["identity_assurance"]["level"] == "T-IAL 0"
        print(f"[PASS] Workflow 2: Legitimate email evaluated -> TSR: LOW, Review Mandated: False, IAL: T-IAL 0 (Unconflated)")

        # Check 4: Upload Valid .eml File
        eml_bytes = (
            b"From: partner@firm.com\r\n"
            b"To: user@acme.com\r\n"
            b"Subject: Logistics Service Invoice #4401\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=\"BOUNDARY_EML\"\r\n"
            b"\r\n"
            b"--BOUNDARY_EML\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Attached is the monthly invoice.\r\n"
            b"\r\n"
            b"--BOUNDARY_EML\r\n"
            b"Content-Type: application/pdf\r\n"
            b"Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n"
            b"\r\n"
            b"%PDF-1.4\r\n"
            b"--BOUNDARY_EML--\r\n"
        )
        r_file = client.post(
            "/api/analyze-file",
            files={"file": ("invoice.eml", eml_bytes, "message/rfc822")},
            data={"retain_evidence": "false"},
        )
        assert r_file.status_code == 200
        file_data = r_file.json()
        assert file_data["subject"] == "Logistics Service Invoice #4401"
        assert file_data["claimed_identity"]["address"] == "partner@firm.com"
        print(f"[PASS] Workflow 3: .eml file uploaded and parsed successfully -> Subject: \"{file_data['subject']}\"")

        # Check 5: Malformed and Oversized Input Safety
        # 5a. Malformed (Multiple From headers)
        malformed = "From: a@b.com\r\nFrom: c@d.com\r\nSubject: Test\r\n\r\nBody"
        r_mal = client.post("/api/analyze", json={"raw_email": malformed, "retain_evidence": False})
        assert r_mal.status_code == 200
        assert r_mal.json()["threat_assessment"]["level"] == "CRITICAL"
        print(f"[PASS] Workflow 4a: Malformed multi-From email handled safely -> TSR: CRITICAL")

        # 5b. Oversized input (> 1 MB)
        oversized = "From: a@b.com\r\n\r\n" + ("X" * (1024 * 1024 + 100))
        r_over = client.post("/api/analyze", json={"raw_email": oversized, "retain_evidence": False})
        assert r_over.status_code == 413
        print(f"[PASS] Workflow 4b: Oversized input (> 1 MB) safely rejected (HTTP 413)")

        # Check 6: Incident History and Incident Details
        r_hist = client.get("/api/incidents?limit=20")
        assert r_hist.status_code == 200
        incidents = r_hist.json()
        assert any(i["id"] == susp_id for i in incidents)

        r_detail = client.get(f"/api/incidents/{susp_id}")
        assert r_detail.status_code == 200
        detail = r_detail.json()
        assert detail["id"] == susp_id
        assert len(detail["audit_events"]) >= 1
        print(f"[PASS] Workflow 5: Incident history listed ({len(incidents)} records) & single detail retrieved")

        # Check 7: Human Review Status Lifecycle & Persistence
        r_patch = client.patch(
            f"/api/incidents/{susp_id}/review",
            json={"status": "CONFIRMED_THREAT", "notes": "Verified by SOC: spoofed display name targeting accounting."},
        )
        assert r_patch.status_code == 200

        r_recheck = client.get(f"/api/incidents/{susp_id}")
        assert r_recheck.status_code == 200
        recheck_data = r_recheck.json()
        assert recheck_data["human_review_status"] == "CONFIRMED_THREAT"
        assert recheck_data["analyst_notes"] == "Verified by SOC: spoofed display name targeting accounting."
        assert recheck_data["assessment"]["human_review_status"] == "CONFIRMED_THREAT"
        print(f"[PASS] Workflow 6: Human review status updated and persisted -> Status: CONFIRMED_THREAT")

        # Check 8: Evidence Integrity Verification
        r_verify = client.post(f"/api/incidents/{susp_id}/verify-evidence")
        assert r_verify.status_code == 200
        ver_data = r_verify.json()
        assert ver_data["status"] == "VERIFIED"
        assert ver_data["matches"] is True
        print(f"[PASS] Workflow 7: Evidence cryptographic integrity verified -> Status: VERIFIED, Matches: True")

        print("==================================================")
        print(" [ALL 7 WORKFLOWS VERIFIED LIVE OVER HTTP SOCKET] ")
        print("==================================================")
    finally:
        proc.terminate()
        proc.wait()

if __name__ == "__main__":
    main()
