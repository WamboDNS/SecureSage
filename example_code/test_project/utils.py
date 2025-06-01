# ./test_project/utils.py
import subprocess
import pickle
import base64

def execute_system_command(command_string):
    try:
        result = subprocess.run(command_string, shell=True, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: {e.stderr}"

def unsafe_deserialize(base64_encoded_data):
    try:
        pickled_data = base64.b64decode(base64_encoded_data)
        return pickle.loads(pickled_data)
    except Exception as e:
        return f"Deserialization error: {e}"