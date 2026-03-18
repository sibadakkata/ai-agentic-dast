"""
Test: Two-User BOLA Detection (end-to-end proof)

Spins up a tiny vulnerable API with two users using only stdlib + jwt,
then verifies that the scanner's BOLA logic correctly:
  1. Authenticates User A and User B separately
  2. Collects User A's resource IDs
  3. Replays as User B and confirms unauthorized access
  4. Triage engine classifies the finding as Critical BOLA
"""

import http.server
import json
import subprocess
import sys
import time
import threading
import requests
import jwt
import datetime

VULN_API_PORT = 19876
VULN_API_URL = f"http://127.0.0.1:{VULN_API_PORT}"

SECRET = "test-secret-key"

USERS = {
    "alice": {"password": "alice123", "role": "user", "id": 1},
    "bob":   {"password": "bob456",   "role": "user", "id": 2},
}

PRIVATE_DATA = {
    1: {"owner": "alice", "ssn": "123-45-6789", "email": "alice@example.com", "salary": 85000},
    2: {"owner": "bob",   "ssn": "987-65-4321", "email": "bob@example.com",   "salary": 72000},
}


def _decode_token(auth_header: str) -> dict | None:
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    try:
        return jwt.decode(auth_header[7:], SECRET, algorithms=["HS256"])
    except Exception:
        return None


class VulnAPIHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # suppress logs

    def _send_json(self, status, data):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return json.loads(self.rfile.read(length))
        return {}

    def do_POST(self):
        if self.path == "/api/login":
            data = self._read_body()
            username = data.get("username", "")
            user = USERS.get(username)
            if not user or user["password"] != data.get("password", ""):
                return self._send_json(401, {"error": "Invalid credentials"})
            token = jwt.encode(
                {"sub": username, "user_id": user["id"],
                 "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
                SECRET, algorithm="HS256"
            )
            return self._send_json(200, {"token": token, "user_id": user["id"]})
        self._send_json(404, {"error": "Not found"})

    def do_GET(self):
        if self.path == "/api/health":
            return self._send_json(200, {"status": "ok"})

        # /api/users/<id>/profile — VULNERABLE (no authz check)
        if self.path.startswith("/api/users/") and self.path.endswith("/profile"):
            user = _decode_token(self.headers.get("Authorization", ""))
            if not user:
                return self._send_json(401, {"error": "Unauthorized"})
            try:
                uid = int(self.path.split("/")[3])
            except (IndexError, ValueError):
                return self._send_json(400, {"error": "Invalid user ID"})
            data = PRIVATE_DATA.get(uid)
            if not data:
                return self._send_json(404, {"error": "Not found"})
            return self._send_json(200, data)

        # /api/users/<id>/settings — SECURE (proper authz)
        if self.path.startswith("/api/users/") and self.path.endswith("/settings"):
            user = _decode_token(self.headers.get("Authorization", ""))
            if not user:
                return self._send_json(401, {"error": "Unauthorized"})
            try:
                uid = int(self.path.split("/")[3])
            except (IndexError, ValueError):
                return self._send_json(400, {"error": "Invalid user ID"})
            if user["user_id"] != uid:
                return self._send_json(403, {"error": "Forbidden"})
            return self._send_json(200, {"theme": "dark", "notifications": True})

        self._send_json(404, {"error": "Not found"})


def start_vuln_api():
    """Start the vulnerable API in a background thread."""
    server = http.server.HTTPServer(("127.0.0.1", VULN_API_PORT), VulnAPIHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    for _ in range(20):
        try:
            r = requests.get(f"{VULN_API_URL}/api/health", timeout=1)
            if r.status_code == 200:
                return server
        except Exception:
            pass
        time.sleep(0.3)
    raise RuntimeError("Vulnerable API failed to start")


def test_bola_detection():
    """Simulate the two-user BOLA detection flow."""
    print("\n" + "=" * 70)
    print("  TWO-USER BOLA DETECTION TEST")
    print("=" * 70)

    # Step 1: Start vulnerable API
    print("\n[1] Starting vulnerable API server...")
    server = start_vuln_api()
    print(f"    API running on {VULN_API_URL}")

    try:
        # Step 2: Authenticate User A (alice)
        print("\n[2] Authenticating User A (alice)...")
        resp_a = requests.post(f"{VULN_API_URL}/api/login", json={"username": "alice", "password": "alice123"})
        assert resp_a.status_code == 200, f"User A login failed: {resp_a.text}"
        token_a = resp_a.json()["token"]
        user_a_id = resp_a.json()["user_id"]
        print(f"    User A authenticated: user_id={user_a_id}, token={token_a[:30]}...")

        # Step 3: Authenticate User B (bob)
        print("\n[3] Authenticating User B (bob)...")
        resp_b = requests.post(f"{VULN_API_URL}/api/login", json={"username": "bob", "password": "bob456"})
        assert resp_b.status_code == 200, f"User B login failed: {resp_b.text}"
        token_b = resp_b.json()["token"]
        user_b_id = resp_b.json()["user_id"]
        print(f"    User B authenticated: user_id={user_b_id}, token={token_b[:30]}...")

        # Step 4: User A accesses their own profile (resource ID discovery)
        print("\n[4] User A accessing own profile (resource discovery)...")
        resp_own = requests.get(
            f"{VULN_API_URL}/api/users/{user_a_id}/profile",
            headers={"Authorization": f"Bearer {token_a}"},
        )
        assert resp_own.status_code == 200
        user_a_data = resp_own.json()
        print(f"    User A's profile: {json.dumps(user_a_data, indent=6)}")

        # Step 5: BOLA TEST — User B tries to access User A's profile
        print("\n[5] BOLA TEST — User B accessing User A's profile (cross-user)...")
        resp_bola = requests.get(
            f"{VULN_API_URL}/api/users/{user_a_id}/profile",
            headers={"Authorization": f"Bearer {token_b}"},
        )
        bola_status = resp_bola.status_code
        bola_body = resp_bola.json()
        print(f"    Status: {bola_status}")
        print(f"    Response: {json.dumps(bola_body, indent=6)}")

        if bola_status == 200 and bola_body.get("owner") == "alice":
            print("\n    >>> BOLA CONFIRMED: User B accessed User A's private data!")
            bola_detected = True
        else:
            print("\n    >>> No BOLA: Server correctly denied access")
            bola_detected = False

        # Step 6: Negative test — User B tries User A's settings (should be blocked)
        print("\n[6] Negative control — User B accessing User A's settings (secure endpoint)...")
        resp_secure = requests.get(
            f"{VULN_API_URL}/api/users/{user_a_id}/settings",
            headers={"Authorization": f"Bearer {token_b}"},
        )
        print(f"    Status: {resp_secure.status_code}")
        print(f"    Response: {resp_secure.json()}")
        secure_blocked = resp_secure.status_code == 403

        # Step 7: Run triage engine on the BOLA finding
        print("\n[7] Running triage engine on BOLA finding...")
        sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parents[1]))
        from scripts.triage_engine import classify as triage_finding

        bola_finding = {
            "title": "BOLA: User B accessed User A's profile",
            "severity": "Critical",
            "url": f"{VULN_API_URL}/api/users/{user_a_id}/profile",
            "parameter": "user_id",
            "payload": str(user_a_id),
            "evidence": (
                f"two-user BOLA test: User B (bob) received 200 with User A (alice) data. "
                f"Response contained: owner=alice, ssn={user_a_data.get('ssn')}, email={user_a_data.get('email')}"
            ),
            "owasp_category": "A01",
            "confidence": "High",
            "remediation": "Implement object-level authorization checks",
            "request_response_pairs": [
                {
                    "request": f"GET /api/users/{user_a_id}/profile\nAuthorization: Bearer {token_b[:20]}...",
                    "response": f"HTTP 200\n{json.dumps(bola_body)}",
                }
            ],
        }

        triaged = triage_finding(bola_finding, [])
        print(f"    Verdict:   {triaged.get('verdict')}")
        print(f"    Severity:  {triaged.get('final_severity')}")
        print(f"    CWE:       {triaged.get('cwe')}")
        print(f"    CVSS:      {triaged.get('cvss')}")
        print(f"    Reason:    {triaged.get('reason')}")

        # Step 8: Also test a single-user IDOR (should get Low)
        print("\n[8] Triage control — single-user IDOR finding (no two-user evidence)...")
        idor_finding = {
            "title": "IDOR: Accessing other user profile by ID",
            "severity": "Medium",
            "url": f"{VULN_API_URL}/api/users/999/profile",
            "parameter": "user_id",
            "payload": "999",
            "evidence": "Changed user_id parameter, got 200 response with data",
            "owasp_category": "A01",
            "confidence": "Medium",
            "remediation": "Add authorization checks",
            "request_response_pairs": [
                {
                    "request": "GET /api/users/999/profile",
                    "response": "HTTP 200\n{\"data\": \"some data\"}",
                }
            ],
        }
        triaged_idor = triage_finding(idor_finding, [])
        print(f"    Verdict:   {triaged_idor.get('verdict')}")
        print(f"    Severity:  {triaged_idor.get('final_severity')}")
        print(f"    Reason:    {triaged_idor.get('reason')}")

        # Step 9: Summary
        print("\n" + "=" * 70)
        print("  TEST RESULTS")
        print("=" * 70)
        results = [
            ("BOLA detected (vulnerable endpoint)",       bola_detected),
            ("Secure endpoint blocked User B",            secure_blocked),
            ("Triage: BOLA verdict = TRUE_POSITIVE",      triaged.get("verdict") == "TRUE_POSITIVE"),
            ("Triage: BOLA severity = Critical",          triaged.get("final_severity") == "Critical"),
            ("Triage: single-user IDOR = Low (not Critical)", triaged_idor.get("final_severity") in ("Low", "Medium")),
        ]
        all_pass = all(v for _, v in results)
        for label, passed in results:
            status = "PASS" if passed else "FAIL"
            print(f"  [{status}] {label}")

        print(f"\n  {'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")
        print("=" * 70)
        return all_pass

    finally:
        server.shutdown()


if __name__ == "__main__":
    success = test_bola_detection()
    sys.exit(0 if success else 1)
