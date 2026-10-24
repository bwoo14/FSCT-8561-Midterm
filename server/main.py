import socket
import pyotp
from handle_auth import hash_password, auth_loop, otp_loop
from handle_logging import logging
from handle_command import authenticate_commands

# Set Variables for host IP and Port number
HOST = "127.0.0.1"
PORT = 12345

# Secret hard coded for usability - NOT MEANT FOR PRODUCTION
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
			logging("INFO", f"Received -- {message.split("|", 1)[0]} -- from {client_address}")

		# Input Data Validation
		if "|" not in message:
			client_socket.send(
				"ERROR|Invalid command format".encode()
				)
			continue


		# Split data by delimiter "|"
		command, content = message.split("|", 1)

		# Handle auth command, pass to helper function
		if command == "AUTH":
			if content == "": # Handle malformed request
					client_socket.send(
						"AUTH_ERROR|Authentication Failed".encode()
					)
			else: # Call helper function
				username = auth_loop(client_socket, client_address, content, USERS)
			
		# Handle OTP Command
		elif command == "OTP":
			try:
				otp_authenticated = False
				if content == "": # Handle malformed request
						client_socket.send(
							"AUTH_ERROR|Authentication Failed".encode()
						)
				else: # Call otp_loop helper function
					otp_loop(client_socket, client_address, content, USERS, username)
			except:
				logging("INFO", f"{client_address} sent OTP before AUTH")
				client_socket.send("AUTH_ERROR|Access Denied - Authenticate with username/password before OTP".encode())

		# Handle client disconnect
		elif command == "EXIT":
			# Confirm connection termination
			client_socket.send(
				"OK|Goodbye".encode()
			)
			# Terminate authentication session. Invalidate session token
			USERS[username]["authenticated"] = False
			USERS[username]["password_verified"] = False
			USERS[username]["session_id"] = None
			connected = False

		else:
			# Handle other commands using helper function authenticate_commands
			if USERS[username]["authenticated"]:
				authenticate_commands(client_socket, client_address, command, content, USERS, username)
			else:
				logging("ERROR", f"Command authentication failed from {client_address}")
				client_socket.send("AUTH_ERROR|Unauthenticated Command".encode())
			
	# Handle reset connection error
	except ConnectionResetError:
		print("Connection reset by client")
		break
	# Handle key error, caused by unauthenticated command
	except NameError:
		logging("INFO", f"{client_address} Sent request without username")
		client_socket.send("AUTH_ERROR|Unauthenticated Command".encode())

	# Handle forced shutdown
	except KeyboardInterrupt as e:
		logging("INFO", e)
		logging("INFO", "Shutting down")

# Close sockets
client_socket.close()
server_socket.close()

print("Server closed")