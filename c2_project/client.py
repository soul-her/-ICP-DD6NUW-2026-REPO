import socket
import platform
import os

SERVER_IP = "127.0.0.1"
PORT = 4444

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((SERVER_IP, PORT))

while True:
    command = client.recv(1024).decode()

    if command == "info":
        info = f"""
System: {platform.system()}
Node: {platform.node()}
Release: {platform.release()}
"""
        client.send(info.encode())

    elif command == "getfile":
        if os.path.exists("sample.txt"):
            with open("sample.txt", "r") as f:
                data = f.read()
            client.send(data.encode())
        else:
            client.send("sample.txt not found".encode())

    elif command == "exit":
        break

client.close()
