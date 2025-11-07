import os, json, hashlib, datetime
from pathlib import Path

LICENSE_FILE = Path("infra/license.key")

# Simple local license structure
def generate_demo_license():
    data = {
        "user": os.getenv("USER", "demo_user"),
        "issued": str(datetime.date.today()),
        "expires": str(datetime.date(2026, 1, 1)),
        "signature": ""  # will fill below
    }
    # Generate a signature hash (pseudo cryptographic)
    raw = f"{data['user']}{data['issued']}{data['expires']}secret_salt"
    data["signature"] = hashlib.sha256(raw.encode()).hexdigest()

    LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(LICENSE_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print("✅ Demo License generated!")
    print(f"License key saved to {LICENSE_FILE}")
    print(f"Valid for: {data['user']} | Expires: {data['expires']}")


def check_license():
    """Called by Streamlit app to validate license"""
    if not LICENSE_FILE.exists():
        return False, "License key missing"

    try:
        with open(LICENSE_FILE) as f:
            data = json.load(f)
        raw = f"{data['user']}{data['issued']}{data['expires']}secret_salt"
        expected_sig = hashlib.sha256(raw.encode()).hexdigest()

        if data["signature"] != expected_sig:
            return False, "License signature invalid"

        if datetime.date.today() > datetime.date.fromisoformat(data["expires"]):
            return False, "License expired"

        return True, f"License verified for {data['user']} (valid until {data['expires']})"
    except Exception as e:
        return False, f"License check error: {e}"


if __name__ == "__main__":
    generate_demo_license()
