import subprocess
import json
import secrets
from flask import Flask, request, jsonify

app = Flask(__name__)
app.config['DEBUG'] = False  # Disable debug in production

with open("config.json") as f:
    config = json.load(f)

API_KEY = config.get("api_key")

@app.route("/generate", methods=["GET"])
def generate_token():
    user_id = request.args.get("user")
    token = secrets.token_urlsafe(16)  # Secure random token
    return jsonify({"user": user_id, "token": token})

@app.route("/execute", methods=["POST"])
def execute_command():
    data = request.get_json()
    cmd = data.get("cmd")

    # Only allow predefined safe commands
    allowed_commands = {
        "uptime": ["uptime"],
        "disk_usage": ["df", "-h"],
        "list_dir": ["ls", "-la"]
    }

    if cmd not in allowed_commands:
        return jsonify({"error": "Invalid command"}), 400

    result = subprocess.run(
        allowed_commands[cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
        text=True
    )

    return jsonify({"output": result.stdout})

@app.route("/data", methods=["POST"])
def upload_data():
    try:
        data = request.get_json(force=True)
        return jsonify({"received": data})
    except Exception:
        return jsonify({"error": "Invalid JSON"}), 400
