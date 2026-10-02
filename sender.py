import socket
import struct
import des

HOST, PORT = "127.0.0.1", 5000
SECRET_KEY = "KUNCIDES"   


def send_msg(sock, ciphertext):
    """Kirim 4 byte panjang text + ciphertext"""
    sock.sendall(struct.pack("!I", len(ciphertext)) + ciphertext)

#Terima n byte data dari socket
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
    print("=== DES SENDER ===")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((HOST, PORT))
    except ConnectionRefusedError:
        print("Gagal connect. Jalankan receiver.py terlebih dahulu.")
        return
    print("Connected to Receiver\n")

    try:
        while True:
            message = input("Enter message (ketik 'exit' untuk keluar): ")
            if message.lower() == "exit":
                break
            cipher = des.encrypt(message, SECRET_KEY)
            print("\nPlaintext : ", message)
            print("Ciphertext:", cipher.hex().upper())
            send_msg(sock, cipher)
            print("Status    : Ciphertext sent\n")

            data = recv_msg(sock)
            if data is None:
                print("Receiver disconnected.")
                break
            print("Ciphertext received:", data.hex().upper())
            print("Decrypted message  :", des.decrypt(data, SECRET_KEY))
            print("-" * 40)
    finally:
        sock.close()


if __name__ == "__main__":
    main()
