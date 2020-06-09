# dark_scan
WORK IN PROGRESS

## About the Project
Dark scan is a port scanner that uses the Tor network to scan traget hosts.<br/>
The connection to Tor network is done automatically without user intercation.<br/>
In addition to port scanning, Dark scan can also resolve URLs and discover hosts on<br/>
the local network using ARP discovery.
<!-- A port scanner that uses the Tor network to scan target hosts.<br/> -->

## Instalation

1. Install Tor service<br/>
```sh
apt update && apt install tor
```
2. Clone the repository<br/>
```sh
git clone https://github.com/gsv-gh/dark_scan.git
```
3. Run dark_scan.py
```sh
cd dark_scan
./dark_scan.py
```
<!-- Requires python 3 and scapy. -->

<!-- Tested on Kali.<br/> -->

## Usage

Execute as root or with sudo.

    Usage: dark_scan.py [OPTIONS]...

        -t      <IP address/URL>        Target
        -p      <Ports>                 Ports to scan
        -r      <URL>                   Resolve host
        -d                              Host discovery on local network
        -nT                             Do not use Tor network (regular TCP SYN scan)

        Examples:
                ./dark_scan.py -t 45.33.32.156 -p 1-1023
                ./dark_scan.py -t scanme.nmap.org -p 22
                ./dark_scan.py -r scanme.nmap.org
                ./dark_scan.py -d


