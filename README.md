# 🐤 Canary

> P2P encrypted vault with a canary in the coal mine — it sniffs incoming syncs for ransomware and refuses to inhale the bad air. When the canary stops singing, the sync stops cold.

NJX Hackathon 2026 · Arc 2 Wildcard

---

## Free vs Pro

| Feature | Free | Pro 🐤 |
|---|---|---|
| Vault create & unlock | ✅ | ✅ |
| Append-only versioning | ✅ | ✅ |
| Manual peer pairing (QR) | ✅ | ✅ |
| Basic LAN sync | ✅ | ✅ |
| Password storage | up to 50 | ∞ unlimited |
| Ransomware canary detection | 🔒 | ✅ |
| Auto-refuse + quarantine on bad sync | 🔒 | ✅ |
| One-click restore from snapshot | 🔒 | ✅ |
| Vault tripwire (.kdbx / .1pux / .enpass) | 🔒 | ✅ |
| Real-time threat dashboard | 🔒 | ✅ |

---

## Quick Start

```bash
pip install -r requirements.txt
python main.py
```

Dashboard: http://localhost:5000

---

## Demo Steps

1. Open dashboard → vault empty, 0 peers → Pro features show 🔒
2. Add Device → scan QR → pair second client (localhost:9000)
3. Add Gmail login → syncs to peer → both show green
4. **FREE:** run `python simulate_ransomware.py` → files poisoned, canary silent
5. Click **"Unlock Canary Pro"** → 🔒 badges flip to 🐤
6. **PRO:** rerun attack → SYNC BLOCKED, signals shown
7. Click "Restore from 2 min ago" → clean files back
8. `.kdbx` untouched on Peer B

---

## Project Layout

```
config.py          — all config incl. CANARY_PRO toggle
main.py            — entry point
core/
  crypto.py        — Argon2id, AES-256-GCM, X25519, Ed25519, Shannon entropy ✅
  test_crypto.py   — 24 crypto primitive tests ✅
  vault.py         — append-only versioned store
  license.py       — Pro gate (require_pro / CanaryLockedError)
guard/
  detector.py      — 🐤 canary detection engine (Pro)
sync/
  peer.py          — P2P TCP + X25519 + mDNS discovery
dashboard/
  app.py           — Flask + SocketIO UI
simulate_ransomware.py  — # MOCK attack simulator
```

---

## Security Disclaimer

**Hackathon prototype. Not audited. Do not use to protect real data.**
Crypto primitives are real (Argon2id, AES-256-GCM, X25519, Ed25519) but the overall system has not been reviewed by a security professional.
