API_KEY = "hardcoded_super_secret_key_12345"

DEFAULT_USERNAME = "admin"

def get_database_url():
    return f"mysql://{DEFAULT_USERNAME}:weakpassword@localhost/mydatabase"