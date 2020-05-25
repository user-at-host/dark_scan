#!/usr/bin/python3
'''
TODO:
	- Add scanning using TOR
	- Add ETA
	- Add banner grabbing
	- Add OS discovery
	- Add check for valid IP addresses
DONE:
	- Add host discovery on local network.
	- Add argument parsing.
	- Resolve URLs to IP address.
	- Parse port ranges
	- Add resolve host option
	- Improve speed
'''

from re import search
from sys import argv
from random import randint
from socket import gethostbyname
from scapy.all import *

TIMEOUT = 2
BLOCK_SIZE = 100

def parse_arguments():
	args = {}
	skip = 0

	if len(argv) == 1:
		print_help()

		exit()

	for i in range(1, len(argv)):
		if skip:
			skip = 0
			continue

		if argv[i] == '-h':
			print_help()
			
			exit()
		elif argv[i] == '-d':
			args["h_discover"] = True

			args["target"] = argv[i + 1]

			skip = 1
		elif argv[i] == '-t':
			args["target"] = argv[i + 1]

			skip = 1
		elif argv[i] == '-p':
			args["port"] = parse_ports(argv[i + 1])

			skip = 1
		elif argv[i] == '-r':
			args["resolve"] = True

			args["target"] = argv[i + 1]

			skip = 1			
		else:
			print("Unknown option: %s" % (argv[i]))

			print_help()

			exit()


	return args


def parse_ports(ports):
	if '-' in ports:
		ports = list(range(int(ports.split('-')[0]), int(ports.split('-')[1]) + 1))

		return ports
	else:
		return [int(ports)]


def print_help():
	print("Usage: dark_scan.py [OPTIONS]...\n")
	print("\t-d\t<IP address/CIDR>\tHost discovery")
	print("\t-t\t<IP address>\t\tTarget")
	print("\t-p\t<Ports>\t\t\tPorts to scan")
	print("\t-r\t<URL>\t\t\tResolve host")
	print()


def host_discovery(target):
	live_hosts = []
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = target), timeout = TIMEOUT, verbose = 0)

	print("Discovering hosts on %s network\n" % (target))

	for snd, rcv in ans:
		live_hosts.append(rcv.psrc)

	for host in live_hosts:
		print("Host: %s is up" % (host))

	print()


def tcp_syn_scan(target, ports):
	open_ports = []
	scanned_ports = 0
	sport = randint(49152, 65535)
	print("Scaning target: %s\n" % (target))

	if len(ports) > 1:
		port_chunks = generate_port_chunks(ports)

	for i in port_chunks:
		ans, unans = sr(IP(dst = target)/TCP(sport = sport, dport = ports[i[0]:i[1]]), timeout = TIMEOUT, verbose = 0)#, inter = 0.01)

		for snd, rcv in ans:
			scanned_ports += 1
			if rcv.haslayer(TCP):
				tcp_layer = rcv.getlayer(TCP)

				if tcp_layer.flags == 20:
						pass
				elif tcp_layer.flags == 18:
					open_ports.append(tcp_layer.sport)

	return open_ports, scanned_ports


def generate_port_chunks(ports):
	port_chunks = []

	for i in range(0, len(ports), 200):
		port_chunks.append([i, i + 200])

	return port_chunks


'''
def tcp_syn_scan(target, ports):
	open_ports = []
	scanned_ports = 0
	ip = IP(dst = target)
	
	print("Scaning %s\n" % (target))

	for i in range(0, len(ports)):
		s_port = randint(49152, 65535)

		ans = sr1(ip/TCP(dport = ports[i], sport = s_port), timeout = TIMEOUT, verbose = 0, inter = 0.001)

		print_percent(scanned_ports, len(ports))

		try:
			if ans.haslayer(TCP):
				if ans[TCP].flags == 20:
					pass
		#			print(i, "Closed")
				elif ans[TCP].flags == 18:
		#			print(i, "Open")
					open_ports.append(ports[i])
		except AttributeError:
			i -= 1

			continue

		scanned_ports += 1

	return open_ports
'''

def print_percent(counter, total_ports):
	print("\rCompleted: %d%%" % (counter * 100 / total_ports), end = '')


def print_results(open_ports, scanned_ports, protocol):
	print('\r', ' ' * 20, '\r', end = '')

	for i in open_ports:
		print("Port %d open %s" % (i, protocol))

	print("\nScanned %d ports" % (scanned_ports))
	print("Found %d open ports" % (len(open_ports)))


def check_address(address):
	pattern = "^[0-9]{1,3}\\."

	if search(pattern, address):
		return address
	else:
		address = resolve_address(address)

		return address


def resolve_address(url):
	print("Resolving: %s" % (url))

	pattern = "^http[s]?://"

	if search(pattern, url):
		url = url.split('//')[1]

	pattern = "\\.*/"

	if search(pattern, url):
		url = url.split('/')[0]
	
	return gethostbyname(url)


def main():
	args = parse_arguments()

	if "h_discover" in args:
		host_discovery(args["target"])
	elif "resolve" in args:
		address = resolve_address(args["target"])
		print("Address: %s" % (address))
	else:
		target = check_address(args["target"])

		ports = args["port"]

		open_ports, scanned_ports = tcp_syn_scan(target, ports)
		print_results(open_ports, scanned_ports, "TCP")


if __name__ == "__main__":
	main()