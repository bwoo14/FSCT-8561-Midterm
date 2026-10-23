import getpass
from getpass import getpass
import hashlib

def auth_password(client_socket):
	password_authenticated = False
	while not password_authenticated:

		# Prompt user to input their username
		username = input("Enter your username: ")

		# Exit if you want
		if username.upper() == "EXIT":
			# Sending "EXIT" command to server
			client_socket.send(
				"EXIT|".encode()
			)
		password = getpass("Password: ")

		# Create string with command ("HELLO") and desired username
		auth_message = f"AUTH|{username}|{password}"

		# Send "AUTH" command to initiate username
		client_socket.send(
			auth_message.encode()
		)

		# Receive response
		response = client_socket.recv(1024)

		# Decode and print the response from the server
		print("Server:", response.decode())

		if "OTP_REQUIRED" in response.decode():
			return True

def auth_mfa(client_socket, session):
	otp_authenticated = False
	while not otp_authenticated:
		# Prompt user for TOTP Code
		otp = input("Enter your TOTP Code: ")

		# Format auth mesage
		otp_message = f"OTP|{otp}"

		# Send "AUTH" command to initiate username
		client_socket.send(
			otp_message.encode()
		)
			# Receive response
		response = client_socket.recv(1024)

		# Decode and print the response from the server
		print("Server:", response.decode())

		if not ("ACCESS DENIED" in response.decode()):
			session["session_id"] = client_socket.recv(1024).decode()
			return True