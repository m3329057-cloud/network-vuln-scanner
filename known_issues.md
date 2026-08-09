# Known Issues - NetSentry Scanner Module

OS detection is unreliable inside VirtualBox NAT/Internal Network setups. The virtual NIC normalizes TCP/IP stack signatures, so Nmap frequently returns Unknown or incorrect guesses even with root privileges. This is a known Nmap limitation in virtualized environments, not a bug in the scanner code.

The Scapy-based ARP scan only works when target hosts are on the same local subnet/broadcast domain as the scanning machine. It will not discover hosts across routed/NAT boundaries even if they are pingable.

Scanning all 65535 ports is significantly slower than the default top-1000 port scan. Full range scans were tested but are not used by default due to impractical scan times for live demos.

Running scan_single on localhost often returns Unknown OS due to Nmap's own fingerprint conflict on loopback interfaces.
