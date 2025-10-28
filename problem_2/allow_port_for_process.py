from bcc import BPF
import pyroute2
import socket
import struct


def ip_to_network_address(ip):
    return struct.unpack("I", socket.inet_aton(ip))[0]


def network_address_to_ip(ip):
    return socket.inet_ntop(socket.AF_INET, struct.pack("I", ip))


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
    print(f"{event.pid}: {event.comm.decode()} - {src_ip}:{event.src_port} -> {dst_ip}:{event.dst_port} was blocked!")


print(f"[+] Monitoring eth0 interface")


with open("allow_port_for_process.c", "r") as f:
    bpf_text = f.read()


ip, ipdb, idx = create_tc()
if not ip:
    exit(-1)

bpf = BPF(text=bpf_text)

# loading TC
fn = bpf.load_func("handle_egress", BPF.SCHED_CLS)

ip.tc(
    "add-filter", 
    "bpf", idx, ":1", 
    fd=fn.fd, name=fn.name, 
    parent="ffff:fff3", # for egress
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