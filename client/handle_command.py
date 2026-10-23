from tcp_scan import tcp_scan
from web_scan import http_scan
from vulnerability_scan import vuln_scan

def verify_and_send(command, client_socket, SESSION, command_function, tool):

	# Send request to server to see if we are authenticated, use sessionID
	client_socket.send(f"{command}|{SESSION['session_id']}".encode())
	response = client_socket.recv(1024).decode()

	# IF response contains "success" then allow the specified function to run
	if "OK" in response:
		print(f"=========== STARTING {tool} ===========")
		command_function()

		footer = f"=========== COMPLETED {tool} ==========="
		print(f"=========== COMPLETED {tool} ===========")
		print(f"="*len(footer))


def handle_command(command, client_socket, SESSION):
	# If the command is scan, verify that the request is authenticated then run TCP scan
	if command == "SCAN":
		verify_and_send(command, client_socket, SESSION, tcp_scan, "TCP SCAN")
	elif command == "WEB":
		verify_and_send(command, client_socket, SESSION, http_scan, "WEBSITE HTTP SCAN")
		verify_and_send(command, client_socket, SESSION, vuln_scan, "WEBSITE VULNERABILITY SCAN")
	elif command == "TRAF":
		# pcap_file = input("Enter name of .pcap file: ")
		pcap_file = "FSCT8561_Operation_Sentinel_Traffic.pcap"
		client_socket.send(f"{command}|{SESSION['session_id']}|{pcap_file}".encode())
		response = client_socket.recv(1024).decode()
		print("Message from server:", response)
	elif command == "MSG":
		message = input("Enter your message: ")
		client_socket.send(f"{command}|{SESSION['session_id']}|{message}".encode())
		response = client_socket.recv(1024).decode()
		print("Message from Server: ", response)


	