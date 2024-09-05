from scapy.all import *
from enum import Enum
import socket

from utils import *

class RelayError(Exception):
    class ErrorType(Enum):
        PIPE_CLOSED = "Closed Pipe!"
        TUNN_AUTH_FAILED = "Tunnel Authentication Failed!"
        MALFORMED_PKT = "Malformed Packet!"
        CONN_FAILED = "Connection Failed!"
        
    def __init__(self, type):
        self.type = type.name
        self.msg = type.value
        super().__init__(self.msg)
        
    def __str__(self):
        return f"{self.type}: {self.msg}"

class Relay:
    def __init__(self, mode, local, remote): 
        self.tunn_conn, self.peer_addr = self._setup_tunn(mode, local, remote)

        self.tcp_input_pipe = UnboundedPipe()
        self.tcp_output_pipe = UnboundedPipe()
        self.udp_pipe = UnboundedPipe()

    def _setup_tunn(self, mode, local, remote):
        try:
            if mode == "client":
                conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                conn.bind(parse_address(local))
                relay_logger.info(f"Started UDP client socket on {local}")
                
                conn.connect(parse_address(remote))
                peer = conn.getpeername()
                conn.send(b"Client: Hello")
                
                buf = conn.recv(1500)
                if buf != b"Server: Accepted":
                    raise RelayError(RelayError.ErrorType.TUNN_AUTH_FAILED)
                
                relay_logger.info(f"Connected to proxy server at {peer}")
                return conn, peer
                        
            elif mode == "server":
                conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                conn.bind(parse_address(local))
                relay_logger.info(f"Started UDP server socket on {local}")
                
                while True:
                    buf, peer = conn.recvfrom(1500)
                    if buf == b"Client: Hello":
                        conn.sendto(b"Server: Accepted", peer)     
                        relay_logger.info(f"Connected to proxy client at {peer}")
                        return conn, peer
        except Exception as e:
            relay_logger.critical(e)
    
    def write(self, pkt):
        try:
            self.tcp_input_pipe.tx(pkt, block=False)
        except queue.Full:
            raise RelayError(RelayError.ErrorType.PIPE_CLOSED)
        
    def read(self):
        try:
            return self.tcp_output_pipe.rx()
        except queue.Empty:
            raise RelayError(RelayError.ErrorType.PIPE_CLOSED)
    
    def start_udp_pipe(self):
        while True:
            try:
                buf = self.tunn_conn.recv(1500)                
                pkt = from_edns_pkt(buf)
                relay_logger.info(f"UDP Pipe: {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} len={pkt[IP].len}")
                
                try:
                    self.udp_pipe.tx(pkt, block=False)
                except queue.Full:
                    raise RelayError(RelayError.ErrorType.PIPE_CLOSED)
            except Exception as e:
                relay_logger.warning(f"UDP Pipe, {e}")
                
    def start_tcp_in_pipe(self):
        while True:
            try:
                try:
                    pkt = self.tcp_input_pipe.rx()  
                except queue.Empty:
                    raise RelayError(RelayError.ErrorType.PIPE_CLOSED)  
                            
                dns_pkt = to_edns_pkt(pkt)
                try:
                    self.tunn_conn.sendto(bytes(dns_pkt), self.peer_addr)
                    relay_logger.info(f"UDP Tunnel Sent: {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} len={pkt[IP].len}")
                except Exception:
                    raise RelayError(RelayError.ErrorType.CONN_FAILED)
            except Exception as e:
                relay_logger.warning(f"TCP IN Pipe, {e}")
                
    def start_tcp_out_pipe(self):
        while True:
            try:
                try:
                    pkt = self.udp_pipe.rx()
                    self.tcp_output_pipe.tx(pkt, block=False)
                except (queue.Full, queue.Empty):
                    raise RelayError(RelayError.ErrorType.PIPE_CLOSED)
            except Exception as e:
                relay_logger.warning(f"TCP OUT Pipe, {e}")

GIGA_EDNS_OPCODE = 65001 

class EdnsError(Exception):
    class ErrorType(Enum):
        DNS_PKT_ERR = "DNS Packet Error!"
        EDNS_DATA_NOT_FOUND = "Edns Data Not Found!"
        
    def __init__(self, type):
        self.type = type.name
        self.msg = type.value
        super().__init__(self.msg)
        
    def __str__(self):
        return f"{self.type}: {self.msg}"

def to_edns_pkt(data):
    try:
        dns_pkt = DNS(
            id=1,
            qr=0,
            opcode=0,
            rd=1,
            qd=DNSQR(qname="leader.ir", qtype="A"),
            ar=DNSRROPT(
                rclass=4096,
                rdata=[EDNS0TLV(
                    optcode=GIGA_EDNS_OPCODE,
                    optlen=len(bytes(data)),
                    optdata=data
                )]
            )
        )
        return dns_pkt
    except Exception:
        raise EdnsError(EdnsError.ErrorType.DNS_PKT_ERR)

def from_edns_pkt(buf):
    try:
        dns_pkt = DNS(buf)
        
        if dns_pkt.arcount == 0 or not isinstance(dns_pkt.ar, DNSRROPT):
            raise EdnsError(EdnsError.ErrorType.EDNS_DATA_NOT_FOUND)
        
        for opt in dns_pkt.ar.rdata:
            if opt.optcode == GIGA_EDNS_OPCODE:
                return IP(opt.optdata)
    
        raise EdnsError(EdnsError.ErrorType.EDNS_DATA_NOT_FOUND)
    except Exception as e:
        raise EdnsError(EdnsError.ErrorType.EDNS_DATA_NOT_FOUND)

def recalculate_chksum(pkt):
    del pkt.chksum
    del pkt[TCP].chksum
    return pkt.__class__(bytes(pkt))

def set_mss_if_any(pkt):
    new_options = []
    for option in pkt[TCP].options:
        if option[0] == "MSS":
            new_options.append(("MSS", min(option[1], 1300)))
        else:
            new_options.append(option)
    pkt[TCP].options = new_options
    return pkt

    
def write_to_nic(tun, relay):
    while True:
        try:
            pkt = relay.read()
            tun_logger.info(f"Writing to NIC: {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} len={pkt[IP].len}")
            tun.send(pkt)  
        except RelayError:
            tun_logger.warning(f"Failed to write packet to NIC, ignoring...")

def read_from_nic(tun, relay):
    while True:
        try:
            pkt = tun.recv()
            if TCP in pkt:
                pkt = set_mss_if_any(pkt)
                pkt = recalculate_chksum(pkt)
                tun_logger.info(f"TUN: {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} len={pkt[IP].len}")
                relay.write(pkt)
                    
        except RelayError:
            tun_logger.warning(f"Failed to read packet from NIC, ignoring...")
