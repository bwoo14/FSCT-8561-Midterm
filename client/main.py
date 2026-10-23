import socket
from getpass import getpass
from handle_auth import auth_mfa, auth_password
from handle_command import handle_command


# Set host and port
HOST = "127.0.0.1"
PORT = 12345

SESSION = {"session_id": ""}

menu_dict = {
	"1": "SCAN",
	"2": "WEB",
	"3": "TRAF",
	"4": "MSG",
	"5": "EXIT"
}

MENU_TEMPLATE = """
Enter one of the following:

[1] Scan TCP Ports
[2] Check Website Security
[3] Analyze Network Traffic
[4] Message Server
[5] Exit

Enter Selection (1-5): 
"""
try:
	# Create socket
	client_socket = socket.socket(
		socket.AF_INET,		# Use IPv4
		socket.SOCK_STREAM	# Use TCP
	)

	# Connect to remote server
	client_socket.connect((HOST, PORT))

	password_authenticated = False
	password_authenticated = auth_password(client_socket)

	otp_authenticated = False
	otp_authenticated = auth_mfa(client_socket, SESSION)


	while True:
		# Prompt user for message to send
		command_selection = input(
			MENU_TEMPLATE
		)
		try:
			command = menu_dict[command_selection]
		except:
			print("Invalid Option")
			continue


		# Check if message is "EXIT"; if yes, terminate connection
		if command.upper() == "EXIT":
			# Sending "EXIT" command to server
			client_socket.send("EXIT|".encode())

			# Get server response, decode, and print
			response = client_socket.recv(1024)
			print("Server:", response.decode())
			# Break loop
			break
		else:
			message = handle_command(command, client_socket, SESSION)
except ConnectionRefusedError:
	print("ERROR: Couldn't establish a connection to the target machine - closing")

except KeyboardInterrupt:
	print("\nINFO: Program terminated by user")
# Close connection
client_socket.close()