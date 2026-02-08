import socket

HOST = "0.0.0.0"
PORT = 4444

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(1)

print("Waiting for client connection...")
conn, addr = server.accept()
print(f"Client connected from {addr}")

while True:
    command = input("Enter command (info/getfile/exit): ")
    conn.send(command.encode())

    if command == "exit":
        break

    data = conn.recv(4096).decode()
    print("Client response:")
    print(data)

conn.close()
