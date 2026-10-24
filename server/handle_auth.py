import hashlib
import pyotp
from handle_logging import logging
import random
import string

LOGIN_ATTEMPT_MAX = 3

def hash_password(password):
	return hashlib.sha256(
		password.encode()
	).hexdigest()


# return true if password correct, otherwise false
def verify_password(entered_hash, stored_hash):
	if entered_hash == stored_hash:
		return True
	else:
		return False
	
# Return true if OTP matches, otherwise False
def verify_otp(secret, otp):
	totp = pyotp.TOTP(secret)
	return totp.verify(otp, valid_window=1)




def auth_loop(client_socket, client_address, content, users):
	try:
		# Set Username and password to what content was
		username, password = content.split("|", 1)
	except ValueError:
		logging("ERROR", f"Malformed authentication message from {client_address}")
		client_socket.send("ERROR|Malformed Message - Authentication Failed".encode())
		return None

	# Verify if username exists, otherwise advise client
	try:
		user = users[username]
	except KeyError:
		logging("ERROR", f"Failed username from {client_address}")
		client_socket.send(
			"AUTH_ERROR|User does not exist".encode()
		)
		return None
	
	if users[username]["login_attempts"] > LOGIN_ATTEMPT_MAX - 1:
		users[username]["locked"] = True
		logging("ERROR", f"{username} account is now locked")
	else:
		logging("INFO", f"Authenticating: {username}")

	# Check if provided username is locked
	if users[username]["locked"]:
		logging("ERROR", f"Too many failed attempts. Authentication blocked for {client_address}")
		client_socket.send("AUTH_ERROR|ACCESS DENIED - Too many failed attempts. Authentication blocked.".encode())
	
	# Verify if password is correct
	elif not verify_password(hash_password(password), users[username]["password_hash"]):
		logging("INFO", f"Incorrect password from {client_address} for username: {username}")
		# Advise client password was incorrect
		client_socket.send(
			"AUTH_ERROR|Incorrect Password".encode()
		)
		# Increase login attempt by 1
		users[username]["login_attempts"] += 1
		logging("INFO", f"{client_address} login attempts remaining: {3 - users[username]["login_attempts"]}")
	else:
		client_socket.send(
			"OK|OTP_REQUIRED - Please input TOTP".encode()
		)

		# Set password verified to true so we can ask for OTP
		users[username]["password_verified"] = True
		return username

def otp_loop(client_socket, client_address, content, users, username):
	otp = content

	try:
		# Lock account if authentication requests exceeds 3
		if users[username]["login_attempts"] > LOGIN_ATTEMPT_MAX - 1:
			users[username]["locked"] = True
			logging("ERROR", f"{username} account is now locked")
		else:
			logging("INFO", f"Authenticating: {username}")

		# If account locked, stop the request and inform the user
		if users[username]["locked"]:
			logging("ERROR", f"Too many failed attempts. Authentication blocked for {client_address}")
			client_socket.send("AUTH_ERROR|ACCESS DENIED - Too many failed attempts. Authentication blocked.".encode())
			return
		
		# Confirm user is password verified before asking for OTP
		if users[username]["password_verified"]:
			if verify_otp(users[username]["totp_secret"], otp):
				# if OTP verified, authenticate user 
				users[username]["authenticated"] = True
				logging(f"INFO", f"Successful login for {username}")
				
				# Reset login count to 0
				users[username]["login_attempts"] = 0

				# Create session_id to use for authentication
				client_socket.send(f"OK|ACCESS GRANTED".encode())

				# create session id and send to client
				users[username]["session_id"] = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
				client_socket.send(users[username]["session_id"].encode())
				
			else:
				# inform user of failed OTP
				logging("INFO", f"Incorrect OTP Code from {username} on {client_address}")
				client_socket.send(f"ERROR|ACCESS DENIED - Incorrect OTP".encode())
				# Increase failed login attempts
				users[username]["login_attempts"] += 1
				logging("INFO", f"{client_address} login attempts remaining: {3 - users[username]["login_attempts"]}")
		else:
			# If user not password verified, tell user to sign in with username and password first
			logging("INFO", f"{client_address} tried signing in without username and password first")
			client_socket.send(f"ERROR|You must sign in with username and password before entering your OTP".encode())
	except KeyError: # Handle error for username, means the user didn't send a AUTH request before OTP 
		logging("INFO", f"{client_address} tried signing in without username and password first")
		client_socket.send(f"ERROR|You must sign in with username and password before entering your OTP".encode())

