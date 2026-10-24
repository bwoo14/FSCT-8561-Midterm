import socket
from getpass import getpass
from handle_auth import auth_mfa, auth_password
from handle_command import handle_command


# Set host and port
HOST = "127.0.0.1"
PORT = 12345

# Session object to store session ID
SESSION = {"session_id": ""}

# Menu dict corresponding number inputs to commands
menu_dict = {
	"1": "SCAN",
	"2": "WEB",
	"3": "TRAF",
	"4": "MSG",
	"5": "EXIT"
}

# Template for menu to be displayed for user
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

	# Begin password authentication requests using helper function
	password_authenticated = False
	password_authenticated = auth_password(client_socket)

	# Begin OTP authentication using Helpder function 
	otp_authenticated = False
	otp_authenticated = auth_mfa(client_socket, SESSION)

	# Maintain connection using While loop
	while True:
		# Prompt user for message to send
		command_selection = input(
			MENU_TEMPLATE
		)
		try: # Ensure valid command selection
			command = menu_dict[command_selection]
		except: # If not, continue loop from start
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
			#  send command to helper function to be sent to server
			message = handle_command(command, client_socket, SESSION)

# Handle case for offline server
except ConnectionRefusedError:
	print("\nERROR: Couldn't establish a connection to the target machine - closing")

# handle case if server goes offline
except ConnectionResetError:
	print("\nERROR: Connection to the target machine was terminated - closing")

# Handle case if user terminates program
except KeyboardInterrupt:
	print("\nINFO: Program terminated by user")
# Close connection
client_socket.close()