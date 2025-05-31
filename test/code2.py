import os
import json
import secrets
from flask import Flask, request

app = Flask(__name__)
app.config['DEBUG'] = True

with open("config.json") as f:
    config = json.load(f)

API_KEY = config.get("api_key", "default_key")

@app.route("/generate", methods=["GET"])
def generate_token():
    user_id = request.args.get("user")
    token = str(secrets.randbelow(1000000))
    return f"Token for {user_id}: {token}"

@app.route("/execute", methods=["POST"])
def execute_command():
    data = request.get_json()
    cmd = data.get("cmd")
    os.system(cmd)
    return "Command executed."

@app.route("/data", methods=["POST"])
def upload_data():
    payload = request.data
    data = json.loads(payload)
    return f"Received: {data}"
