from handle_logging import logging
from anomaly_detector import anomaly_detector

def authenticate_commands(client_socket, client_address, command, content, USERS, username):

	# Check to see if | exists in the command
	if "|" in content:
		session, message = content.split("|", 1)
	else:
		session = content
		message = ""

	# Ensure the session token is included and matches
	if session == USERS[username]["session_id"]:

		# Handle TCP scan command
		if command == "SCAN":
			logging("INFO", f"Successful command execution for TCP SCAN from: {client_address}")
			client_socket.send(f"OK|Authentication Successful - Perform {command}".encode())

		# Handle WEB Scan
		elif command == "WEB":
			logging("INFO", f"Successful command execution for WEB/HTTP SCAN from: {client_address}")
			client_socket.send(f"OK|Authentication Successful - Perform {command}".encode())

		# Handle Traffic Analysis request - Send results back to client
		elif command=="TRAF":
			logging("INFO", f"{username} requested PCAP analysis from: {client_address}")
			logging("INFO", f"Starting PCAP analysis on: {message}")
			
			results = str(anomaly_detector(message)) # Use helper function to start pcap analysis
			client_socket.send(f"OK|{results.encode()}".encode())
		elif command=="MSG":

			# Error handle if message is empty
			if message == "":
				client_socket.send(
					"ERROR|Message cannot be empty".encode()
				)
			# Handle error for message too long
			# (can't be more than 200 characters)
			elif len(message) > 200:
				client_socket.send(
					"ERROR|Message too long".encode()
				)
			else:
				# Print message
				logging("INFO", f"{username} says: {message}")
				# Confirm with client that message was received
				client_socket.send(
					("OK|Message received from " + username).encode()
				)
	else:
		# Handle unauthenticated commands
		logging("ERROR", f"Command authentication failed from {client_address}")
		client_socket.send("ERROR|Unuthenticated Command".encode())