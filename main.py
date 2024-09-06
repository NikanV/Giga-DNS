from scapy.all import *
from threading import Thread

from utils import *
from tunman import *

DEFAULT_ROUTE = "via 172.30.240.1 dev eth0"

def setup_tun(mode, subnet, remote, tun_name="giga-dns"):
    t = TunTapInterface(iface=tun_name, mode_tun=True)
    
    run_cmd(f"ip addr add {subnet} dev {tun_name}")
    run_cmd(f"ip link set up dev {tun_name}")

    global DEFAULT_ROUTE
    route_info = run_cmd(f"sudo ip route show default")
    DEFAULT_ROUTE = " ".join(route_info.split()[1:]) if route_info is not None else DEFAULT_ROUTE
    
    if mode == "client":
        run_cmd(f"sudo ip route del default")
        run_cmd(f"sudo ip route add default via 172.16.0.1 dev {tun_name}")   
        run_cmd(f"sudo ip route add {parse_address(remote)[0]} {DEFAULT_ROUTE}")
    elif mode == "server":
        run_cmd("sudo sysctl -w net.ipv4.ip_forward=1")
        run_cmd("iptables -t nat -A POSTROUTING -s 172.16.0.0/24 ! -d 172.16.0.0/24 -j MASQUERADE")
    
    return t

def check_args(args):
    if args.mode == "client" and args.remote is None:
        main_logger.critical("You should specify a remote address! (Client Mode)")
        return False
    
    if args.mode == "server" and args.remote is not None:
        main_logger.warning("Remote address is ignored! (Server Mode)")
        
    if "172.16.0" not in args.subnet:
        main_logger.warning("Changing the subnet may cause some issues!")
    
    return True

def cleanup(mode, remote):
    if mode == "client":
        run_cmd(f"sudo ip route del default", silent=True)
        run_cmd(f"sudo ip route add default {DEFAULT_ROUTE}", silent=True)
        run_cmd(f"sudo ip route del {parse_address(remote)[0]}", silent=True)
    elif mode == "server":
        run_cmd("iptables -t nat -D POSTROUTING -s 172.16.0.0/24 ! -d 172.16.0.0/24 -j MASQUERADE", silent=True)

def main():
    try:
        args = ArgParser().parse()
        
        if not check_args(args):
            return
        
        tun = setup_tun(args.mode, args.subnet, args.remote)
        relay = Relay(args.mode, args.local, args.remote)

        threads = [
            Thread(target=relay.start_udp_pipe, daemon=True),
            Thread(target=relay.start_tcp_in_pipe, daemon=True),
            Thread(target=relay.start_tcp_out_pipe, daemon=True),
            Thread(target=write_to_nic, args=(tun, relay), daemon=True),
            Thread(target=read_from_nic, args=(tun, relay), daemon=True)
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
    except KeyboardInterrupt:
        print("")
        main_logger.info("Cleaning Up...")
    finally:
        cleanup(args.mode, args.remote)
        sys.exit(0)
    
if __name__ == "__main__":
    main()
    