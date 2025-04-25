import json
from hashlib import sha256
import os

def hash_password(password):
    salt = os.urandom(16).hex()
    salted_password = password.encode() + salt.encode()
    hashed_password = sha256(salted_password).hexdigest()
    return hashed_password, salt

filePath = "users.json"

try:
    with open(filePath, "r") as file:
        users = json.load(file)

    for user in users:
        if "Salt" not in user:  # Only hash passwords that aren't already hashed
            password = user['Password']
            hashed_password, salt = hash_password(password)
            user['Password'] = hashed_password
            user['Salt'] = salt

    with open(filePath, "w") as file:
        json.dump(users, file, indent=4)

    print("Passwords successfully hashed and updated!")

except FileNotFoundError:
    print("users.json file not found.")
