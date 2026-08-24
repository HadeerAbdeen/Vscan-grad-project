"""
Quick demo / test script for the VScan encryption + defanging layer.

Run from project root:
    python test_encryption.py

Demonstrates:
  1. Fernet encryption + decryption of arbitrary bytes.
  2. Integrity verification (SHA-256 constant-time compare).
  3. Quarantine vault — 3-layer defanging (Fernet + AES-ZIP + .malware
     extension) so a quarantined sample cannot be auto-executed.
"""
from pathlib import Path

from app.utils.encryption import (
    encrypt_bytes,
    decrypt_bytes,
    sha256_hex,
    verify_integrity,
)
from app.services.quarantine_service import QuarantineService


GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"


def section(title: str):
    print(f"\n{YELLOW}{'=' * 60}\n {title}\n{'=' * 60}{RESET}")


# ── TEST 1: Fernet encrypt / decrypt ───────────────────────────────────────
section("TEST 1 — Fernet Encryption (AES-128 + HMAC)")

original = b"This is the EICAR test virus file content."
print(f"Original bytes:  {original}")

ciphertext = encrypt_bytes(original)
print(f"{RED}Ciphertext:      {ciphertext[:60]}...{RESET}")
print(f"  -> length: {len(ciphertext)} bytes (encrypted, unreadable)")

recovered = decrypt_bytes(ciphertext)
print(f"{GREEN}Decrypted back:  {recovered}{RESET}")

assert recovered == original, "Encryption round-trip failed!"
print(f"{GREEN}PASS - encryption is reversible with the correct key{RESET}")


# ── TEST 2: Integrity verification (tamper detection) ─────────────────────
section("TEST 2 — Upload Integrity (SHA-256)")

file_bytes = b"Hello VScan. This is a fake upload."
client_hash = sha256_hex(file_bytes)
print(f"Client computes SHA-256: {client_hash}")

print(f"\nCase A: Server receives the SAME bytes")
ok = verify_integrity(file_bytes, client_hash)
print(f"  verify_integrity() -> {GREEN if ok else RED}{ok}{RESET}")
assert ok

print(f"\nCase B: Bytes were TAMPERED in transit")
tampered = file_bytes + b"X"
ok = verify_integrity(tampered, client_hash)
print(f"  verify_integrity() -> {GREEN if not ok else RED}{ok}{RESET}")
assert not ok
print(f"{GREEN}PASS - tampering is detected and would be rejected (HTTP 400){RESET}")


# ── TEST 3: Defanged vault — 3-layer neutralisation ────────────────────────
section("TEST 3 — Defanged Vault (Fernet + AES-ZIP + .malware extension)")

malware_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
fake_scan_id = 9999
stored_filename = "demo_malware.txt"

result = QuarantineService.quarantine_bytes(fake_scan_id, malware_bytes, stored_filename)
print(f"Quarantine result: {result}")
assert result["success"]

vault_file = Path(result["vault_path"])
print(f"\n{GREEN}Layer 3 - Defanged extension:{RESET}")
print(f"  filename: {vault_file.name}")
assert vault_file.name.endswith(".malware.zip")
print(f"  -> ends with .malware.zip - OS will not auto-execute")

print(f"\n{GREEN}Layer 2 - Password-protected ZIP wrapper:{RESET}")
print(f"  packaging: {result['packaging']}")
print(f"  size on disk: {vault_file.stat().st_size} bytes")

raw_on_disk = vault_file.read_bytes()
assert raw_on_disk[:2] == b"PK", "Not a ZIP file!"
print(f"  -> valid ZIP magic (PK..) - opens with any unzip tool, password = 'infected'")

print(f"\n{GREEN}Layer 1 - Fernet encryption (inside the ZIP):{RESET}")
if malware_bytes in raw_on_disk:
    print(f"{RED}FAIL - original malware bytes found on disk!{RESET}")
else:
    print(f"  -> original EICAR bytes are NOT visible on disk")

decrypted = QuarantineService.read_quarantined_bytes(fake_scan_id, stored_filename)
print(f"\n{GREEN}Admin recovery (reverses all 3 layers):{RESET}")
print(f"  {decrypted}")
assert decrypted == malware_bytes
print(f"{GREEN}PASS - admin recovered original bytes via unzip -> Fernet decrypt{RESET}")

vault_file.unlink()
print(f"\n(cleanup) removed {vault_file}")

print(f"\n{GREEN}{'=' * 60}\n  All 3 tests passed\n{'=' * 60}{RESET}")
