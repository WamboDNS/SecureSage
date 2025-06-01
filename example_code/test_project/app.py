# ./test_project/app.py
from config import API_KEY, get_database_url
from utils import execute_system_command, unsafe_deserialize
import os 

def initialize_app():
    print(f"Initializing with API Key: {API_KEY}") 
    db_url = get_database_url()
    print(f"Connecting to DB: {db_url}")

def handle_user_request(user_data):
    result = execute_system_command(f"ls -l {user_data}")
    print(f"Command result: {result}")

def process_serialized_object(encoded_object_string):
    obj = unsafe_deserialize(encoded_object_string)
    print(f"Processed object: {obj}")

if __name__ == "__main__":
    initialize_app()

    malicious_path_input = "nonexistent_file; echo 'PWNED!'"
    handle_user_request(malicious_path_input)

    malicious_pickle_b64 = b"gASVHgAAAAAAAACMCF9faW1wb3J0X19lWAMAAABvc5SUTlgEAAAAZWNobyB2dWxuZXJhYmxlX3BpY2tlk5RSlC4="
    process_serialized_object(malicious_pickle_b64)