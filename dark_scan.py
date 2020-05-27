#!/usr/bin/python3
'''
TODO:
	- Add check for valid IP addresses
	- Add check for local network scanning
	- Add check for Tor service (installed and running)
	- Add ETA
	- Add banner grabbing
	- Add OS discovery
DONE:
	- Add host discovery on local network.
	- Add argument parsing.
	- Resolve URLs to IP address.
	- Parse port ranges
	- Add resolve host option
	- Improve speed
	- Add scanning using TOR
'''

import socks
import socket
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

		args["tor_scan"] = True

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
		elif argv[i] == '-nt':
			args["tor_scan"] = False
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
	print("\t-d\t<IP address/CIDR>\tHost discovery on local network")
	print("\t-t\t<IP address/URL>\tTarget")
	print("\t-p\t<Ports>\t\t\tPorts to scan")
	print("\t-r\t<URL>\t\t\tResolve host")
	print("\t-nt\t\t\t\tDo not use Tor network (regular TCP SYN scan)")
	print("\n\tExamples:")
	print("\t\t./dark_scan.py -t 45.33.32.156 -p 1-1023")
	print("\t\t./dark_scan.py -r scanme.nmap.org")
	print("\t\t./dark_scan.py -d 192.168.1.1/24")
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

	if len(ports) > 1:
		port_chunks = generate_port_chunks(ports)
	else:
		port_chunks = [[0, 1]]

	for i in port_chunks:
		ip = IP(dst = target)
		tcp = TCP(sport = sport, dport = ports[i[0]:i[1]])
		ans, unans = sr(ip/tcp, timeout = TIMEOUT, verbose = 0)

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


def tor_scan(target, ports):
	open_ports = []
	scanned_ports = 0

	socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050, True)

	for port in ports:
		try:
			s = socks.socksocket()

			scanned_ports += 1

			s.connect((target, port))
			s.close()

			open_ports.append(port)
		except socks.GeneralProxyError:
			pass

	return open_ports, scanned_ports


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
		ports = args["port"]
		target = check_address(args["target"]) 

		print("Scaning target: %s\n" % (target))

		if args["tor_scan"]:
			open_ports, scanned_ports = tor_scan(target, ports)
		else:
			open_ports, scanned_ports = tcp_syn_scan(target, ports)

		print_results(open_ports, scanned_ports, "TCP")


if __name__ == "__main__":
	main()