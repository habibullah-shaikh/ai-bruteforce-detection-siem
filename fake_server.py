import socket

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('127.0.0.1', 2222))
server.listen(5)
print("Fake SSH-like server listening on port 2222...")

while True:
    conn, addr = server.accept()
    print(f"Connection attempt from {addr}")
    conn.close()