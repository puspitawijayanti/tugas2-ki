import socket
import sys
import threading

from aes import (
    MODE_CBC,
    MODE_ECB,
    ask_key,
    random_ascii,
    recv_line,
    seal,
    send_line,
    validate_id,
    validate_key,
)

DEFAULT_PORT = 5000


class KdcServer:
    def __init__(self, keys=None, mode=MODE_CBC):
        self.keys = dict(keys or {})
        self.mode = mode
        self.lock = threading.Lock()
        self.listener = None
        self.running = False
        self.log = print

    def set_key(self, user_id, key_text):
        validate_id(user_id)
        key = validate_key(key_text)
        with self.lock:
            self.keys[user_id] = key

    def set_mode(self, mode):
        with self.lock:
            self.mode = mode

    def handle_request(self, line):
        parts = line.split("|")
        if len(parts) != 4 or parts[0] != "REQ":
            return "ERR|bad request format"
        _, id_a, id_b, n1 = parts
        if not (n1.isascii() and n1.isdigit()):
            return "ERR|nonce must be a number"
        with self.lock:
            ka = self.keys.get(id_a)
            kb = self.keys.get(id_b)
            mode = self.mode
        if ka is None or kb is None:
            return "ERR|unknown ID"
        if id_a == id_b:
            return "ERR|sender and receiver must differ"
        ks = random_ascii(16)
        for_a = seal(ks + f"{id_a}|{id_b}|{n1}".encode("ascii"), ka, mode)
        ticket = seal(ks + id_a.encode("ascii"), kb, mode)
        self.log(f"[KDC] new Ks for {id_a} <-> {id_b}: {ks.decode('ascii')}")
        return "RESP|" + for_a.hex() + "|" + ticket.hex()

    def handle_connection(self, conn, addr):
        with conn:
            conn.settimeout(10)
            try:
                reader = conn.makefile("r", encoding="ascii", newline="\n")
                line = recv_line(reader)
                self.log(f"[KDC] {addr[0]}:{addr[1]} -> {line}")
                reply = self.handle_request(line)
                send_line(conn, reply)
                self.log(f"[KDC] {addr[0]}:{addr[1]} <- {reply}")
            except (OSError, ValueError):
                return

    def accept_loop(self):
        while self.running:
            try:
                conn, addr = self.listener.accept()
            except OSError:
                break
            threading.Thread(target=self.handle_connection, args=(conn, addr), daemon=True).start()

    def start(self, host, port):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind((host, port))
        self.listener.listen(5)
        self.running = True
        threading.Thread(target=self.accept_loop, daemon=True).start()
        return self.listener.getsockname()[1]

    def stop(self):
        self.running = False
        if self.listener:
            try:
                self.listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.listener.close()


def show_users(server):
    with server.lock:
        items = sorted(server.keys.items())
        mode = "CBC" if server.mode == MODE_CBC else "ECB"
    print(f"Encryption mode: {mode}")
    for user_id, key in items:
        print(f"  {user_id}: {key.decode("ascii")}")


def menu(server):
    while True:
        print("\n1. Show users and keys  2. Set/change user key  3. Change mode  4. Quit")
        choice = input("> ").strip()
        if choice == "1":
            show_users(server)
        elif choice == "2":
            user_id = input("User ID: ").strip()
            try:
                validate_id(user_id)
            except ValueError as error:
                print(error)
                continue
            server.set_key(user_id, ask_key(f"master key for {user_id}"))
            print("Key saved.")
        elif choice == "3":
            name = input("Mode (ecb/cbc): ").strip().lower()
            if name in ("ecb", "cbc"):
                server.set_mode(MODE_ECB if name == "ecb" else MODE_CBC)
                print(f"Mode set to {name.upper()}.")
            else:
                print("Unknown mode.")
        elif choice == "4":
            return


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    server = KdcServer()
    for user_id in ("alice", "bob"):
        server.set_key(user_id, ask_key(f"master key for {user_id}"))
    server.start("0.0.0.0", port)
    print(f"KDC listening on port {port}")
    try:
        menu(server)
    except (KeyboardInterrupt, EOFError):
        pass
    server.stop()


if __name__ == "__main__":
    main()