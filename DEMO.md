# 🐤 Canary Demo Walkthrough

**NJX Hackathon 2026 · Arc 2 Wildcard**
Deadline: Sunday 12pm · Demo: Sunday 1–4pm

---

## Setup (do once before the room fills)

```bash
# Terminal A — Canary node (Peer B, the victim)
python main.py
# → Dashboard at http://localhost:5001

# Terminal B — attack terminal (keep minimised until Act II)
# (nothing to run yet)
```

Open **http://localhost:5001** in Chrome. Keep it visible on the projector.

---

## Act I — Free Tier: the coal mine has no canary

### Step 1 — Show the locked dashboard

- Dashboard opens. Vault is empty. 0 peers.
- Pro features are **greyed out with 🔒 badges**: Detection, Quarantine, Restore, Threat feed.
- Password counter shows `0 / 50`.

**Say:** "Free tier — you get an encrypted syncing vault, but no protection."

### Step 2 — Add a password

Click **Add Password** and fill in:
- Service: `Gmail`
- Username: `demo@gmail.com`
- Password: `Hunter2!`

Hit **Save**. Counter increments to `1 / 50`. Versions list shows `v1`.

### Step 3 — Run the ransomware attack on Free tier

Switch to Terminal B:

```bash
python simulate_ransomware.py
```

Expected output:

```
🦠  Canary Ransomware Simulator  (# MOCK)
   Target  : 127.0.0.1:9000
   Payload : 20 entries
   Signals present: CANARY_FILE, TRIPWIRE, ENTROPY

😬  SYNC ACCEPTED — Free tier, no canary protection.
   20 poisoned entries ingested without detection.
   Flip to Canary Pro and rerun to see the canary scream.
```

**Point at the dashboard** — no alert, no red banner. The threat feed is empty.

**Say:** "Twenty ransomware payloads — AAA canary tripwire, encrypted .kdbx, high-entropy blobs — all silently accepted. Free tier has no canary."

---

## Act II — Flip to Pro: the canary starts singing

### Step 4 — Unlock Canary Pro

Click **Unlock Canary Pro** in the top-right of the dashboard.

Watch live:
- 🔒 badges flip to 🐤 instantly (no page reload — SocketIO `license:changed`)
- Password counter changes to `1 / ∞`
- Detection, Quarantine, Restore, Threat feed all light up green

**Say:** "One click. Pro is live. The canary is armed."

### Step 5 — Rerun the attack on Pro tier

Back in Terminal B:

```bash
python simulate_ransomware.py
```

Expected output:

```
🦠  Canary Ransomware Simulator  (# MOCK)
   Target  : 127.0.0.1:9000
   Payload : 20 entries
   Signals present: CANARY_FILE, TRIPWIRE, ENTROPY

🚨  SYNC BLOCKED — Canary Pro caught the attack!
   Signals  : CANARY_FILE, TRIPWIRE, ENTROPY
   Flagged  : AAA_canary_tripwire.txt, passwords.kdbx, document_0000.enc…
   quarantined → quarantine/1234567890_attacker/
```

**Point at the dashboard** — red SYNC BLOCKED alert appears in the threat feed with all three signals.

**Say:** "Three signals fired simultaneously — canary file, vault tripwire, high-entropy payload. Sync refused. Batch quarantined. The canary screamed and the coal mine sealed."

### Step 6 — Restore from snapshot (Pro)

In the dashboard sidebar under **Versions**, click the `v1` snapshot → **Restore**.

```
✅ Restored 1 entry from v1 (Gmail / demo@gmail.com)
```

**Say:** "One-click restore to any point before the attack. The vault is append-only — nothing can be overwritten, only rolled back."

---

## Act III — The kicker

Point at Terminal A logs — `.kdbx` tripwire fired before a single bit of ransom payload touched the vault entries. The password database is untouched.

**Say:** "The canary in the coal mine doesn't wait for damage — it sees the first poisoned breath and seals the mine."

---

## Cheat Sheet (if something goes wrong)

| Problem | Fix |
|---|---|
| `Connection refused` on attack | Check `python main.py` is running, port 9000 free |
| Dashboard blank | Hard-refresh Chrome (Cmd+Shift+R) |
| Pro toggle didn't fire signals | Make sure you clicked **Unlock Canary Pro** first, then reran the script |
| No versions to restore | Add at least one password first (Step 2) |
| `Address already in use` | `lsof -ti:9000 \| xargs kill` and `lsof -ti:5001 \| xargs kill` |

---

## Signal reference

| Signal | What triggers it | Demo entry |
|---|---|---|
| `CANARY_FILE` | filename starts with `AAA_canary` | `AAA_canary_tripwire.txt` |
| `TRIPWIRE` | `.kdbx / .1pux / .enpass` | `passwords.kdbx` |
| `ENTROPY` | Shannon entropy > 0.85 | `document_*.enc` (random bytes) |
| `MASS_CHANGE` | > 10% of vault entries changed in 5 min | fires if vault has ≤ 200 entries and 20 arrive |
