# dark_scan
WORK IN PROGRESS

A port scanner that uses the Tor network to scan target hosts.<br/>
Make sure that Tor service is installed.

Tested on Kali.<br/>
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


