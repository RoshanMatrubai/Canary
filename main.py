import config
from dashboard.app import app, socketio, init_app

tier = "Pro 🐤" if config.CANARY_PRO else "Free"
print(f"🐤 Canary node starting… (tier: {tier})")
print(f"[canary] dashboard → http://localhost:{config.DASHBOARD_PORT}")

init_app()
socketio.run(app, host="0.0.0.0", port=config.DASHBOARD_PORT, debug=False, use_reloader=False, allow_unsafe_werkzeug=True)
