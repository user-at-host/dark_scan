# dark_scan
WORK IN PROGRESS  
This is a very old project I once worked on. It did not recieve any updates for about 5 years.
Now I decided to reincarnate it, so updates are expected.

## About the Project
Dark scan is a port scanner that uses the Tor network to scan targets.<br/>
The connection to Tor network is done automatically without user interaction.<br/>
In addition to port scanning, Dark scan can also resolve URLs and discover hosts on<br/>
the local network using ARP scanning.<br/>
<!-- A port scanner that uses the Tor network to scan target hosts.<br/> -->

## Instalation

1. Install Tor service<br/>
```bash
apt update && apt install tor
```
2. Clone the repository<br/>
```bash
git clone https://github.com/gsv-gh/dark_scan.git
```
3. Set execution permissions and run the scanner
```bash
cd dark_scan

chmod u+x dark_scan.py

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


