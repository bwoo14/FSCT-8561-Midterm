import socket
import pyotp
from handle_auth import hash_password, auth_loop, otp_loop
from handle_logging import logging
from handle_command import authenticate_commands

# Set Variables for host IP and Port number
HOST = "127.0.0.1"
PORT = 12345

# secret = pyotp.random_base32()
# print(f"Secret: {secret}")
secret = "JRATOCVUTNQESGNCSPUC5WHKQAEO3BXJ"
USERS = {
	"brandon": {
		"password_hash": hash_password("brandon"),
		"totp_secret": secret,
		"password_verified": False,
		"authenticated": False,
		"login_attempts": 0,
		"locked": False,
		"session_id": None
	}
}


# Create socket
server_socket = socket.socket(
	socket.AF_INET,		# Use IPv4
	socket.SOCK_STREAM	# Use TCP
)

# Bind to specified host/port then listen
server_socket.bind((HOST, PORT))
server_socket.listen(1)


logging("INFO", "Server is waiting for a connection...")

# Accept a client connection
client_socket, client_address = server_socket.accept()
# client_socket.send("OK|Connection to Server Successful".encode())
logging("INFO", f"Connected by: {client_address}")

connected = True

while connected:
	try:
		data = client_socket.recv(1024)
		if not data:
			logging("INFO", f"Client {client_address} disconnected unexpectedly")
			break
		# Decode data
		message = data.decode()
		if "AUTH" in message:
			logging("INFO", f"Received authentication (AUTH) request from {client_address}")
		elif "OTP" in message:
			logging("INFO", f"Received MFA 6 Digit code (OTP) request from {client_address}")
		else:
			logging("INFO", f"Received -- {message} -- from {client_address}")

		# Input Data Validation
		if "|" not in message:
			client_socket.send(
				"ERROR|Invalid command format".encode()
				)
			continue


		# Split data by delimiter "|"
		command, content = message.split("|", 1)

		if command == "AUTH":
			if content == "":
					client_socket.send(
						"ERROR|Authentication Failed".encode()
					)
			else:
				username = auth_loop(client_socket, client_address, content, USERS)
			
		
		elif command == "OTP":
			otp_authenticated = False
			if content == "":
					client_socket.send(
						"ERROR|Authentication Failed".encode()
					)
			else:
				otp_loop(client_socket, client_address, content, USERS, username)

		elif command == "EXIT":
			# Confirm connection termination
			client_socket.send(
				"OK|Goodbye".encode()
			)
			# Terminate connection
			USERS[username]["authenticated"] = False
			USERS[username]["password_verified"] = False
			USERS[username]["session_id"] = None
			connected = False

		else:
			if USERS[username]["authenticated"]:
				authenticate_commands(client_socket, client_address, command, content, USERS, username)
			else:
				logging("ERROR", f"Command authentication failed from {client_address}")
				client_socket.send("ERROR|Unauthenticated Command".encode())
			

	except ConnectionResetError:
		print("Connection reset by client")
		break