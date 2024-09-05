# Giga-DNS

**Giga-DNS** is a VPN solution that works by Layer 4 protocol swapping. It encapsulates TCP data (most commonly) from the client into DNS packets and sends them to a proxy server. The proxy server then unpacks the TCP data from the DNS packet and forwards it to the actual destination server.

This technique enables secure communication by leveraging the DNS protocol, often helping bypass network restrictions that block standard VPNs or TCP traffic.

## Usage

To run Giga-DNS, use the following command-line arguments:

```bash
sudo python3 main.py --mode {client,server} [--local LOCAL] [--remote REMOTE] [--subnet SUBNET]

Options:
  --mode, -m          Mode to run the script in: (client or server) (required)
  --local, -l         The local address to bind on (default: 0.0.0.0:9091)
  --remote, -r        The remote server address (required for client mode)
  --subnet, -s        The subnet range to listen on (default: 172.16.0.2/24)
```

### Example commands

Run as a client:
```bash
sudo python3 main.py -m client -l 0.0.0.0:7070 -r 5.34.192.13:9091 -s 172.16.0.2/24
```
Run as a server:
```bash
sudo python3 main.py -m server -l 0.0.0.0:9091 -s 172.16.0.1/24
```

## Installation

To install the required dependencies:
```bash
pip install -r requirements.txt
```