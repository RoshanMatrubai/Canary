from config import CANARY_PRO

tier = "Pro 🐤" if CANARY_PRO else "Free"
print(f"🐤 Canary node starting… (tier: {tier})")
