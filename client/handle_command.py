from tcp_scan import tcp_scan
from web_scan import http_scan
from vulnerability_scan import vuln_scan

# Helper function to format commands with session ID and send to server
def verify_and_send(command, client_socket, SESSION, command_function, tool):

	# Send request to server to see if we are authenticated, use sessionID
	client_socket.send(f"{command}|{SESSION['session_id']}".encode())
	response = client_socket.recv(1024).decode()

	# IF response contains "success" then allow the specified function to run
	if "OK" in response:
		print(f"=========== STARTING {tool} ===========")
		command_function()

		# Format logging
		footer = f"=========== COMPLETED {tool} ==========="
		print(f"=========== COMPLETED {tool} ===========")
		print(f"="*len(footer))


def handle_command(command, client_socket, SESSION):
	# If the command is scan, verify that the request is authenticated then run TCP scan

	print("INFO - SENDING BAD SESSION ID, COMMAND SHOULD FAIL")

	if command == "SCAN": # Handle scan request by client
		verify_and_send(command, client_socket, SESSION, tcp_scan, "TCP SCAN")
	elif command == "WEB": # Handle web request by client
		verify_and_send(command, client_socket, SESSION, http_scan, "WEBSITE HTTP SCAN")
		verify_and_send(command, client_socket, SESSION, vuln_scan, "WEBSITE VULNERABILITY SCAN")
	elif command == "TRAF":# Handle traffic analysis request by client
		pcap_file = "FSCT8561_Operation_Sentinel_Traffic.pcap"

		# Format request and send to server
		client_socket.send(f"{command}|{SESSION['session_id']}|{pcap_file}".encode())

		# Print the response from the server
		response = client_socket.recv(1024).decode()
		print("Message from server:", response)

		# Extract the part after OK|
		data_string = response.split("|", 1)[1].strip()

		# Remove the b"..." wrapper
		data_string = data_string[2:-1]

		# format to dict
		report = eval(data_string)
		print("\n=== RESULT FROM PCAP ANALYSIS ===\n")
		for key in report.keys():
			print(f"{key}: {report[key]}")
	elif command == "MSG": # Handle simple message request

		# Ask user to input message
		message = input("Enter your message: ")

		# Send request and wait for response
		client_socket.send(f"{command}|{SESSION['session_id']}|{message}".encode())
		response = client_socket.recv(1024).decode()
		print("Message from Server: ", response)


	