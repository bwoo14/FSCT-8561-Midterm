# from scapy.all import rdpcap
from scapy.all import TCP, UDP
from scapy.all import IP
from scapy.all import Raw
from scapy.all import PcapReader

def anomaly_detector(pcap_file):
	# create dictionary for source IP
	source_ips = {}

	# Create list for alert of IPs
	alerted_ips = []


	# Count of TCP and UDP packets
	tcp_count = 0
	udp_count = 0

	if not pcap_file.lower().endswith((".pcap", ".pcapng")):
		return "File not of network capture type (.pcap or .pcapng)"

	
	try:
		with PcapReader(pcap_file) as pcap_reader:  # Using pcapreader as it is faster than rdpcap
			# Iterate over packet
			for pkt in pcap_reader:
				# Check if TCP or UDP, add to count
				if TCP in pkt:
					tcp_count += 1
				elif UDP in pkt:
					udp_count += 1
				# If UDP or TCP and IPv4 proceed 
				if (TCP in pkt or UDP in pkt) and IP in pkt:

					# get packet ip and time
					pkt_ip = pkt[IP].src
					pkt_time = float(pkt.time)

					# if IP exists proceed,
					if pkt_ip in source_ips.keys(): 

						# Get past times for iteration
						past_times = source_ips[pkt_ip]
						for time in past_times:
							if pkt_time - time > 5:
								# Remove packets older than 5 seconds
								source_ips[pkt_ip].remove(time)

						source_ips[pkt_ip].append(pkt_time) # Add pkt_time to source ip

						# If there are more than 20 packets form the same IP and we haven't alerted already, print alert
						if len(source_ips[pkt_ip]) > 20 and pkt_ip not in alerted_ips:
							alerted_ips.append(pkt_ip)
							print(f"ALERT - High traffic load from {pkt_ip}")

					else:
						# if IP doesn't exist in dictioary yet, add it
						source_ips[pkt_ip] = [pkt_time]

		print(
		f"""
		TCP Packets: {tcp_count}
		UDP Packets: {udp_count}
		Suspicious IPs: {len(alerted_ips)}
		"""
		)
		return {
			"TCP Packets": tcp_count,
			"UDP Packets": udp_count,
			"Suspicious IPs Amount": len(alerted_ips),
			"Suspicious IPs": alerted_ips
		}
	except FileNotFoundError as e:
		return f"Error: {e}"
