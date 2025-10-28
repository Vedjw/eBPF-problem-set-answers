from bcc import BPF
import pyroute2
import socket
import struct
import json

# TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


def parse_tcp_flags(flags):
    found_flags = ""
    if flags & FIN:
        found_flags += "FIN; "
    if flags & SYN:
        found_flags += "SYN; "
    if flags & RST:
        found_flags += "RST; "
    if flags & PSH:
        found_flags += "PSH; "
    if flags & ACK:
        found_flags += "ACK; "
    if flags & URG:
        found_flags += "URG; "
    if flags & ECE:
        found_flags += "ECE; "
    if flags & CWR:
        found_flags += "CWR;"

    return found_flags


def ip_to_network_address(ip):
    return struct.unpack("I", socket.inet_aton(ip))[0]


def network_address_to_ip(ip):
    return socket.inet_ntop(socket.AF_INET, struct.pack("I", ip))


def create_bpf_block_list(bpf):
    block_list = bpf.get_table("block_list")

    with open("block_list.json", "r") as f:
        ports_to_block = json.loads(f.read())

    print("[+] Reading and parsing block_list.json")

    for port in ports_to_block:
        try:
            port = int(port)
        except ValueError:
            print(f"[-] Invalid port: {port}")
            continue

        print(f"[+] Adding port {port} to block list")
        block_list[block_list.Key(port)] = block_list.Leaf(1)


def create_tc():
    ip = pyroute2.IPRoute()
    idx = ip.link_lookup(ifname="eth0")[0]

    try:
        ip.tc("del", "clsact", idx)
    except Exception:
        pass

    ip.tc("add", "clsact", idx)
    return ip, idx

def parse_blocked_event(cpu, data, size):
    event = bpf["blocked_events"].event(data)
    src_ip = network_address_to_ip(event.src_ip)
    dst_ip = network_address_to_ip(event.dst_ip)
    flags = parse_tcp_flags(event.tcp_flags)
    print(f"{event.pid}: {event.comm.decode()} - {src_ip}:{event.src_port} -> {dst_ip}:{event.dst_port} Flags: {flags} was blocked!")


print(f"[+] Monitoring eth0 interface")


with open("tcp_mon_block.c", "r") as f:
    bpf_text = f.read()


ip, ipdb, idx = create_tc()
if not ip:
    exit(-1)

bpf = BPF(text=bpf_text)
create_bpf_block_list(bpf)

# loading TC
fn = bpf.load_func("handle_ingress", BPF.SCHED_CLS)

ip.tc(
    "add-filter", 
    "bpf", idx, ":1", 
    fd=fn.fd, name=fn.name, 
    parent="ffff:fff2", # for ingress
    classid=1, 
    direct_action=True)
bpf["blocked_events"].open_perf_buffer(parse_blocked_event)


print("[+] Monitoring started\n")
while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        break

ip.tc("del", "clsact", idx)
ipdb.release()