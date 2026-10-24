import socket
import nmap

def get_host_input(prompt):
	# Check if hostname is valid
	invalid = True
	while invalid:
		target = input(prompt)
		try:
			target_ip = socket.gethostbyname(target)
			print ("INFO - IP Resolved - Target IP is ", target_ip)
		except socket.gaierror:
			print("ERROR: Invalid hostname or IP address")
			continue
		break
	return target_ip

# Get port input
def get_port_input(prompt, starting_port=0):
	invalid = True
	while invalid:
		# Make sure user entered an integer
		try:
			port = int(input(prompt))
		except:
			print("ERROR: Enter a valid integer between 1 and 65535")
			continue

		# Ensure that the end port is bigger than the starting port
		if port < starting_port:
			print("ERROR: End Port must be larger than Starting Port")
			continue

		# make sure port within correct range
		if not (1 <= port <= 65535):
			print("ERROR: Invalid Port Number - Port must be between 1 and 65535")
			continue
		
		if (starting_port != 0) and (port - starting_port > 1000):
			print("ERROR: Port Range too large. Try something smaller")
		else:
			return port

def tcp_scan():
	# Get inputs from user
	target = get_host_input("Target host: ")
	start_port = get_port_input("Start port: ")
	end_port = get_port_input("End port: ", starting_port=start_port)

	# Quit if range is too large
	if end_port - start_port >= 1000:
		print("ERROR: Range too large")
		quit()

	# Create scanner
	scanner = nmap.PortScanner()
	scanner.scan(target, f"{start_port}-{end_port}")



	results = scanner[target]["tcp"]


	print()
	# If open_ports less than 1, print no open ports. Else, print open ports
	if len(results) < 1:
		print("No open ports found in the selected range")
	else:
		print(f"{'Port':<10} {'State':<10} {'Service'}")
		print("-" * 40)
		for port in results.keys():
			if results[port]["name"] == "":
				print(f"{port:<10} {results[port]["state"]:<10} unknown")
			else:
				print(f"{port:<10} {results[port]["state"]:<10} {results[port]["name"]}")
	print()
	print("Scan Complete.")

	