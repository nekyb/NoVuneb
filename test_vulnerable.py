"""
Test file with intentional security vulnerabilities for NoVuneb testing.
DO NOT use this code in production!
"""

import os
import pickle
import subprocess

password = "hardcoded_password_123"

API_KEY = "sk-1234567890abcdef"

def execute_command(user_input):
    os.system(f"ls {user_input}")

def sql_query(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return query

def deserialize_data(data):
    return pickle.loads(data)

def run_shell_command(cmd):
    subprocess.call(cmd, shell=True)

def weak_crypto_example():
    import hashlib
    password_hash = hashlib.md5(b"mypassword").hexdigest()
    return password_hash

def assert_check(value):
    assert value > 0, "Value must be positive"

def eval_user_input(user_code):
    result = eval(user_code)
    return result

def dangerous_open(filename):
    with open(filename, 'r') as f:
        return f.read()

if __name__ == "__main__":
    print("This is a vulnerable test file for NoVuneb")
    print(f"Password: {password}")
    print(f"API Key: {API_KEY}")
