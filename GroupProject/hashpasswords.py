import hashlib
import json
import os

def hash_password(password):
	password_salt = os.urandom(16)
	salted_password = password.encode() + password_salt
	password_hash = hashlib.sha256(salted_password).hexdigest()
	return password_hash, password_salt.hex()
	
def password_store(password):
	with open(password.json, "rb") as file:
		json.dump(password, file)

def passwordLoader():
	with open(password.json, "rb") as file:
		password = json.load(file)
	return password
	
def verify_password(password, hashed_password, salt):
    salted_password = password.encode() + salt.encode()
    return hashlib.sha256(salted_password).hexdigest() == hashed_password