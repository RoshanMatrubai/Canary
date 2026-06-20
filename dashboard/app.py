"""
dashboard/app.py — Flask + SocketIO dashboard.

Routes
  GET  /                   main dashboard
  GET  /status             JSON: tier, counts, node_id, versions
  GET  /vault/entries      JSON list of entries (passwords masked)
  POST /vault/add          add a new entry
  GET  /vault/versions     list snapshot versions
  POST /vault/restore      restore from a snapshot (Pro-gated)
  GET  /pairing/qr         ASCII QR for peer pairing
  POST /license/activate   flip Pro on  → emit license:changed
  POST /license/deactivate flip Pro off → emit license:changed
  GET  /threats            list recent threat events

SocketIO events emitted to clients
  license:changed   {pro: bool}
  threat:alert      {type, node_id, signals?, severity?, detail?, timestamp}
  vault:updated     {entry_count, version_count, versions}
  peer:discovered   {node_id, host, port}
"""
import os
import threading
from datetime import datetime, timezone

import config
import core.license as _lic
from core.license import CanaryLockedError, require_pro
from core.vault import (
    add_entry,
    create_vault,
    list_entries,
    list_versions,
    restore_version,
    unlock_vault,
)
from sync.peer import PeerNode

from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO, emit as ws_emit

app = Flask(__name__)
app.secret_key = os.urandom(32)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ---------------------------------------------------------------------------
# Module-level state — single user, hackathon demo
# ---------------------------------------------------------------------------

_state: dict = {
    "vsk": None,
    "vault_dir": config.VAULT_DIR,
    "peer_node": None,
    "threats": [],   # list[dict], newest first, capped at 50
    "peers": {},     # node_id → {host, port}
}


# ---------------------------------------------------------------------------
# Vault helpers
# ---------------------------------------------------------------------------

def _ensure_vault() -> bytes:
    try:
        vsk = create_vault(_state["vault_dir"], config.VAULT_MASTER_PASSWORD)
        print(f"[dashboard] vault created at {_state['vault_dir']}")
    except FileExistsError:
        vsk = unlock_vault(_state["vault_dir"], config.VAULT_MASTER_PASSWORD)
        print(f"[dashboard] vault unlocked at {_state['vault_dir']}")
    return vsk


def _entry_count() -> int:
    if not _state["vsk"]:
        return 0
    try:
        return len(list_entries(_state["vault_dir"], _state["vsk"]))
    except Exception:
        return 0


def _emit_vault_update() -> None:
    try:
        versions = list_versions(_state["vault_dir"])
        socketio.emit("vault:updated", {
            "entry_count": _entry_count(),
            "version_count": len(versions),
            "versions": versions,
        })
    except Exception:
        pass


# ---------------------------------------------------------------------------
# PeerNode callbacks — called from background threads
# ---------------------------------------------------------------------------

def _on_sync_event(event: dict) -> None:
    event["timestamp"] = datetime.now(timezone.utc).isoformat()
    _state["threats"].insert(0, event)
    _state["threats"] = _state["threats"][:50]
    socketio.emit("threat:alert", event)


def _on_peer_discovered(node_id: str, host: str, port: int) -> None:
    _state["peers"][node_id] = {"host": host, "port": port}
    socketio.emit("peer:discovered", {"node_id": node_id, "host": host, "port": port})


# ---------------------------------------------------------------------------
# Startup — called from main.py before socketio.run()
# ---------------------------------------------------------------------------

def init_app() -> None:
    _state["vsk"] = _ensure_vault()
    threading.Thread(target=_start_peer_node, daemon=True).start()


def _start_peer_node() -> None:
    node = PeerNode(
        config_dir=".canary",
        vault_entry_count=_entry_count(),
        on_sync_event=_on_sync_event,
        on_peer_discovered=_on_peer_discovered,
    )
    try:
        node.start()
    except Exception as exc:
        print(f"[dashboard] peer node failed: {exc}")
    _state["peer_node"] = node


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/status")
def status():
    count = _entry_count()
    pro = _lic.is_pro()
    node = _state["peer_node"]
    return jsonify({
        "pro": pro,
        "entry_count": count,
        "limit": config.FREE_PASSWORD_LIMIT,
        "at_limit": not pro and count >= config.FREE_PASSWORD_LIMIT,
        "peer_count": len(_state["peers"]),
        "peers": [
            {"node_id": nid, **info}
            for nid, info in _state["peers"].items()
        ],
        "node_id": node.node_id if node else "starting…",
        "versions": list_versions(_state["vault_dir"]),
    })


@app.route("/vault/entries")
def vault_entries():
    if not _state["vsk"]:
        return jsonify({"error": "vault locked"}), 403
    try:
        entries = list_entries(_state["vault_dir"], _state["vsk"])
        display = [
            {
                "id": e.get("id"),
                "service": e.get("service", ""),
                "username": e.get("username", ""),
                "created_at": e.get("created_at", ""),
            }
            for e in entries
        ]
        return jsonify({"entries": display})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/vault/add", methods=["POST"])
def vault_add():
    if not _state["vsk"]:
        return jsonify({"error": "vault locked"}), 403
    data = request.get_json(force=True) or {}
    service = (data.get("service") or "").strip()
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if not service:
        return jsonify({"error": "service is required"}), 400
    try:
        entry_id = add_entry(_state["vault_dir"], _state["vsk"], {
            "service": service,
            "username": username,
            "password": password,
        })
        _emit_vault_update()
        return jsonify({"ok": True, "id": entry_id})
    except CanaryLockedError as exc:
        return jsonify({"error": str(exc), "locked": True}), 402
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/vault/versions")
def vault_versions():
    return jsonify({"versions": list_versions(_state["vault_dir"])})


@app.route("/vault/restore", methods=["POST"])
def vault_restore():
    try:
        require_pro("Restore from Snapshot")
    except CanaryLockedError as exc:
        return jsonify({"error": str(exc), "locked": True}), 402
    data = request.get_json(force=True) or {}
    version = data.get("version")
    if not version:
        return jsonify({"error": "version is required"}), 400
    try:
        entries = restore_version(_state["vault_dir"], _state["vsk"], version)
        return jsonify({
            "ok": True,
            "version": version,
            "entry_count": len(entries),
            "entries": [
                {"service": e.get("service", ""), "username": e.get("username", "")}
                for e in entries
            ],
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/pairing/qr")
def pairing_qr():
    node = _state["peer_node"]
    if not node:
        return jsonify({"error": "peer node not ready"}), 503
    return jsonify({"qr": node.pairing_qr(), "node_id": node.node_id})


@app.route("/license/activate", methods=["POST"])
def license_activate():
    _lic.activate()
    if _state["peer_node"]:
        _state["peer_node"].vault_entry_count = _entry_count()
    socketio.emit("license:changed", {"pro": True})
    return jsonify({"ok": True, "pro": True})


@app.route("/license/deactivate", methods=["POST"])
def license_deactivate():
    _lic.deactivate()
    socketio.emit("license:changed", {"pro": False})
    return jsonify({"ok": True, "pro": False})


@app.route("/threats")
def threats():
    return jsonify({"threats": _state["threats"]})


# ---------------------------------------------------------------------------
# SocketIO
# ---------------------------------------------------------------------------

@socketio.on("connect")
def on_connect():
    # Sync new client to current state immediately
    ws_emit("license:changed", {"pro": _lic.is_pro()})
    try:
        versions = list_versions(_state["vault_dir"])
        ws_emit("vault:updated", {
            "entry_count": _entry_count(),
            "version_count": len(versions),
            "versions": versions,
        })
    except Exception:
        pass
