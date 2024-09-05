import logging.handlers
import subprocess
import queue
import argparse
import logging

logging.basicConfig(    
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.handlers.RotatingFileHandler("giga-dns.log", maxBytes=5*1024*1024, backupCount=2)
    ]
)

main_logger = logging.getLogger("Giga-DNS")
relay_logger = logging.getLogger("Giga-DNS::Relay")
tun_logger = logging.getLogger("Giga-DNS::TUN")

class UnboundedPipe:
    def __init__(self):
        self._queue = queue.Queue()
        
    def tx(self, item, block=True):
        self._queue.put(item, block=block)
        
    def rx(self, block=True):
        return self._queue.get(block=block)
    
class ArgParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("--mode", "-m", choices=["client", "server"], required=True, help="Mode to run the script in: (client or server)")
        self.parser.add_argument("--local", "-l", default="0.0.0.0:9091", help="The local address to bind on")
        self.parser.add_argument("--remote", "-r", help="The remote server address")
        self.parser.add_argument("--subnet", "-s", default="172.16.0.2/24", help="The subnet range to listen on")
    
    def parse(self):
        return self.parser.parse_args()
    
    def get_def(self, arg):
        return self.parser.get_default(arg)
        

def parse_address(subnet):
    parsed = subnet.split(":")
    return (parsed[0], int(parsed[1])) if len(parsed) == 2 else (parsed[0], None)

def run_cmd(cmd, silent=False):
    try:
        res = subprocess.run(cmd, shell=True, check=True, text=True, capture_output=True)
        if not silent:
            main_logger.info(f"{cmd}")
        return res.stdout
    except subprocess.CalledProcessError as e:
        if not silent:
            main_logger.error(f"{cmd}: {e.stderr}")
        return None