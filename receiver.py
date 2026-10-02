import socket
import struct
import des

HOST, PORT = "127.0.0.1", 5000
SECRET_KEY = "KUNCIDES"   

def send_msg(sock, ciphertext):
    """Kirim 4 byte panjang text + ciphertext"""
    sock.sendall(struct.pack("!I", len(ciphertext)) + ciphertext)


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def recv_msg(sock):
    header = recv_exact(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack("!I", header)
    return recv_exact(sock, length)


def main():
    print("=== DES RECEIVER ===")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    print("Waiting for connection...")
    conn, addr = server.accept()
    print("Connected to Sender\n")

    try:
        while True:
            data = recv_msg(conn)
            if data is None:
                print("Sender disconnected.")
                break
            print("Ciphertext received:", data.hex().upper())
            print("Decrypted message  :", des.decrypt(data, SECRET_KEY))

            reply = input("\nEnter reply: ")
            cipher = des.encrypt(reply, SECRET_KEY)
            send_msg(conn, cipher)
            print("Ciphertext sent    :", cipher.hex().upper())
            print("-" * 40)
    finally:
        conn.close()
        server.close()


if __name__ == "__main__":
    main()
