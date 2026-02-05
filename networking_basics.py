import socket

def port_scan(target):
    print(f"\nScanning {target} (ports 1–1024)...\n")

    for port in range(1, 1025):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)  # handles timeouts

        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"
                print(f"[OPEN] Port {port} - {service}")
        except:
            pass
        finally:
            sock.close()

if __name__ == "__main__":
    target_ip = input("Enter target IP: ")
    port_scan(target_ip)
