from bcc import BPF
import socket
from ctypes import *
import pyroute2
from pyroute2 import NetlinkError
import re
import sys
from args import *
import os
import time

args = args_parser()
tw = args.time
sw = args.size
mask = args.mask
log_dir = args.logDir
devices = args.devices.split(',')
e = args.endpointThreshold

print("USING NICs:", end=' ')
print(devices)
ipr = pyroute2.IPRoute()
b = BPF(src_file="stitch.ebpf.c", cflags=[f"-DTIME_NS={tw}000000",
					  f"-DSIZE_B={sw}",
					  f"-DIP_MASK={mask}", f"-DSUS={e}"])
fn = b.load_func("handle_ingress", BPF.XDP)
f_egress = b.load_func("handle_egress", BPF.SCHED_CLS)

for d in devices:
    eth = ipr.link_lookup(ifname=d)[0]

    try:
        ipr.tc("add", "clsact", eth)
    except NetlinkError as e:
        if 'File exists' in str(e):
            pass
        else:
            raise

    b.attach_xdp(d, fn, 0)
    ipr.tc("add-filter", "bpf", eth, ':1', fd=f_egress.fd, name=f_egress.name,
            parent='ffff:fff3', classid=1, direct_action=True)

if log_dir != None:
    out_file = f"{log_dir}/{sw}B_{tw}ms.txt"

    try:
        f = open(f"{out_file}", 'a')
    except FileNotFoundError:
        os.makedirs(log_dir)
        f = open(f"{out_file}", 'a')
else:
    f = sys.stdout

def unsignedToSigned(n, byte_count): 
  return int.from_bytes(n.to_bytes(byte_count, 'little', signed=False), 'little', signed=True)

def bitwise_xor_bytes(a, b):
    result_int = int.from_bytes(a, byteorder="big") ^ int.from_bytes(b, byteorder="big")
    return result_int.to_bytes(4, byteorder="big")

def print_event(cpu, data, size):
    data = b["output"].event(data)
    ip_xor = data.init_addr.to_bytes(4, 'little')
    eno1 = socket.inet_aton("10.50.1.2")
    res_ip = socket.inet_ntoa(bitwise_xor_bytes(ip_xor, eno1))
    if(re.match("10.50.1.*", res_ip)):
        print(f"INIT FID -> SADDR:{res_ip}, PORT:{data.init_port}, \
        PROTO:{data.init_proto}, SZ:{data.init_sz}, \
        T:{unsignedToSigned(data.init_tm, 8)}", end=" ", file=f)
    else:
        print(f"INIT FID -> SADDR:{ip_xor}, PORT:{data.init_port}, \
        PROTO:{data.init_proto}, SZ:{data.init_sz}, \
        T:{unsignedToSigned(data.init_tm, 8)}", end=" ", file=f)

    print(f"RESULT -> DADDR:{socket.inet_ntoa(data.res_addr.to_bytes(4, 'little'))}, \
    DPORT:{data.res_port}, PROTO:{data.res_proto}, SZ:{data.res_sz}, \
    T:{unsignedToSigned(data.res_tm, 8)}", file=f)

b["output"].open_ring_buffer(print_event)
print("Setup complete. Listening for events...")
while 1:
    try:
        b.ring_buffer_poll()
    except KeyboardInterrupt:
        break

for d in devices:
    eth = ipr.link_lookup(ifname=d)[0]
    b.remove_xdp(d, 0)
    ipr.tc("del", "clsact", eth)

f.close()
