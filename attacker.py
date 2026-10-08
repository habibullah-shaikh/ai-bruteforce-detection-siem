import socket
import time

target_ip = '127.0.0.1'
target_port = 2222

print("Starting brute force simulation...")
for i in range(500):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect((target_ip, target_port))
        s.close()
    except:
        pass

print("Brute force simulation complete — 500 attempts sent")