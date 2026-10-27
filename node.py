import socket
import sys
import threading

from aes import (
    MODE_CBC,
    MODE_ECB,
    ask_key,
    new_nonce,
    recv_line,
    seal,
    send_line,
    unseal,
    validate_id,
    validate_key,
)

KDC_DEFAULT_PORT = 5000
PEER_DEFAULT_PORT = 6000
STEP_TIMEOUT = 10


class ProtocolError(Exception):
    pass


class Session:
    def __init__(self, conn, reader, key, peer_id):
        self.conn = conn
        self.reader = reader
        self.key = key
        self.peer_id = peer_id
        self.send_lock = threading.Lock()


class Node:
    def __init__(self, my_id, master_key, kdc_addr, listen_port=PEER_DEFAULT_PORT, log=print):
        self.my_id = my_id
        self.master_key = master_key
        self.kdc_addr = kdc_addr
        self.listen_port = listen_port
        self.log = log
        self.mode = MODE_CBC
        self.session = None
        self.inbox = []
        self.state_lock = threading.Lock()
        self.listener = None

    def start_listener(self):
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("0.0.0.0", self.listen_port))
        self.listener.listen(5)
        self.listen_port = self.listener.getsockname()[1]
        threading.Thread(target=self.accept_loop, daemon=True).start()
        return self.listen_port

    def accept_loop(self):
        while True:
            try:
                conn, addr = self.listener.accept()
            except OSError:
                break
            threading.Thread(target=self.handle_incoming, args=(conn, addr), daemon=True).start()

    def stop(self):
        if self.listener:
            try:
                self.listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.listener.close()
        if self.session:
            self.close_session()

    def request_session_key(self, peer_id):
        n1 = new_nonce()
        request = f"REQ|{self.my_id}|{peer_id}|{n1}"
        with socket.create_connection(self.kdc_addr, timeout=STEP_TIMEOUT) as conn:
            self.log(f"[1] A -> KDC  {request}")
            send_line(conn, request)
            reader = conn.makefile("r", encoding="ascii", newline="\n")
            reply = recv_line(reader)
        self.log(f"[2] KDC -> A  {reply}")
        parts = reply.split("|")
        if parts[0] == "ERR":
            raise ProtocolError(f"KDC refused: {parts[1] if len(parts) > 1 else reply}")
        if len(parts) != 3 or parts[0] != "RESP":
            raise ProtocolError("bad reply from KDC")
        try:
            plain = unseal(bytes.fromhex(parts[1]), self.master_key)
            fields = plain[16:].decode("ascii").split("|")
        except ValueError as error:
            raise ProtocolError(f"cannot read KDC reply ({error}), check the master key")
        if fields != [self.my_id, peer_id, n1]:
            raise ProtocolError("KDC reply does not match the request")
        ks = plain[:16]
        self.log(f"    Ks = {ks.decode('ascii')}")
        return ks, parts[2]

    def connect_peer(self, peer_id, host, port):
        if self.session:
            raise ProtocolError("a session is already active, close it first")
        ks, ticket_hex = self.request_session_key(peer_id)
        conn = socket.create_connection((host, port), timeout=STEP_TIMEOUT)
        try:
            reader = conn.makefile("r", encoding="ascii", newline="\n")
            ticket_line = f"TICKET|{ticket_hex}"
            self.log(f"[3] A -> B    {ticket_line}")
            send_line(conn, ticket_line)
            challenge = recv_line(reader)
            self.log(f"[4] B -> A    {challenge}")
            tag, _, body = challenge.partition("|")
            if tag != "CHALLENGE":
                raise ProtocolError(f"peer refused: {body or challenge}")
            n2 = int(unseal(bytes.fromhex(body), ks).decode("ascii"))
            answer = "RESPONSE|" + seal(str(n2 + 1).encode("ascii"), ks, self.mode).hex()
            self.log(f"[5] A -> B    {answer}")
            send_line(conn, answer)
            verdict = recv_line(reader)
            self.log(f"    B says: {verdict}")
            if verdict != "AUTH_OK":
                raise ProtocolError(f"peer refused: {verdict}")
        except BaseException:
            conn.close()
            raise
        self.start_session(conn, reader, ks, peer_id)

    def handle_incoming(self, conn, addr):
        reader = conn.makefile("r", encoding="ascii", newline="\n")
        try:
            conn.settimeout(STEP_TIMEOUT)
            line = recv_line(reader)
            self.log(f"\n[3] A -> B    {line}   (from {addr[0]})")
            tag, _, ticket_hex = line.partition("|")
            if tag != "TICKET":
                raise ProtocolError("expected TICKET")
            if self.session:
                raise ProtocolError("busy")
            plain = unseal(bytes.fromhex(ticket_hex), self.master_key)
            ks = plain[:16]
            peer_id = plain[16:].decode("ascii")
            n2 = new_nonce()
            challenge = "CHALLENGE|" + seal(n2.encode("ascii"), ks, self.mode).hex()
            self.log(f"[4] B -> A    {challenge}")
            send_line(conn, challenge)
            answer = recv_line(reader)
            self.log(f"[5] A -> B    {answer}")
            tag, _, body = answer.partition("|")
            value = int(unseal(bytes.fromhex(body), ks).decode("ascii"))
            if tag != "RESPONSE" or value != int(n2) + 1:
                raise ProtocolError("wrong answer to challenge")
            send_line(conn, "AUTH_OK")
        except (ProtocolError, OSError, ValueError) as error:
            self.log(f"\nIncoming connection rejected: {error}")
            try:
                send_line(conn, f"AUTH_FAIL|{error}")
            except OSError:
                pass
            conn.close()
            return
        self.start_session(conn, reader, ks, peer_id)

    def start_session(self, conn, reader, key, peer_id):
        conn.settimeout(None)
        session = Session(conn, reader, key, peer_id)
        with self.state_lock:
            if self.session is not None:
                conn.close()
                return
            self.session = session
        self.log(f"\nSession established with {peer_id}. Ks = {key.decode('ascii')}")
        threading.Thread(target=self.receive_loop, args=(session,), daemon=True).start()

    def receive_loop(self, session):
        try:
            while True:
                line = recv_line(session.reader)
                tag, _, body = line.partition("|")
                if tag == "BYE":
                    break
                if tag != "MSG":
                    continue
                try:
                    text = unseal(bytes.fromhex(body), session.key).decode("ascii")
                except ValueError as error:
                    self.log(f"\nCould not decrypt message: {error}")
                    continue
                self.inbox.append((session.peer_id, text))
                self.log(f"\n[{session.peer_id}] {text}\n    cipher: {body}")
        except OSError:
            pass
        finally:
            self.end_session(session)

    def end_session(self, session):
        with self.state_lock:
            if self.session is not session:
                return
            self.session = None
        try:
            session.conn.close()
        except OSError:
            pass
        self.log(f"\nSession with {session.peer_id} closed.")

    def send_message(self, text):
        session = self.session
        if session is None:
            raise ProtocolError("no active session")
        if not text or not text.isascii():
            raise ProtocolError("message must be non-empty ASCII")
        sealed = seal(text.encode("ascii"), session.key, self.mode).hex()
        with session.send_lock:
            send_line(session.conn, "MSG|" + sealed)
        self.log(f"    cipher: {sealed}")

    def close_session(self):
        session = self.session
        if session is None:
            raise ProtocolError("no active session")
        try:
            with session.send_lock:
                send_line(session.conn, "BYE")
        except OSError:
            pass
        self.end_session(session)


def show_status(node):
    mode = "CBC" if node.mode == MODE_CBC else "ECB"
    print(f"ID: {node.my_id}   listening on port {node.listen_port}   mode: {mode}")
    print(f"KDC: {node.kdc_addr[0]}:{node.kdc_addr[1]}   master key: {node.master_key.decode("ascii")}")
    session = node.session
    if session:
        print(f"Session with {session.peer_id}, Ks = {session.key.decode('ascii')}")
    else:
        print("No active session")


def chat_mode(node):
    if node.session is None:
        raise ProtocolError("no active session")
    print("Chat mode. Type a message and press Enter. Type /menu to go back.")
    while True:
        text = input("you> ").strip()
        if text == "/menu":
            return
        if not text:
            continue
        try:
            node.send_message(text)
        except (ProtocolError, OSError) as error:
            print(f"Error: {error}")
            if node.session is None:
                return


def menu(node):
    while True:
        print("\n1. Start session  2. Send message  3. Change master key  "
              "4. Change mode  5. Status  6. Close session  7. Quit")
        choice = input("> ").strip()
        try:
            if choice == "1":
                peer_id = validate_id(input("Peer ID: ").strip())
                host = input("Peer IP: ").strip()
                port_text = input(f"Peer port [{PEER_DEFAULT_PORT}]: ").strip()
                node.connect_peer(peer_id, host, int(port_text) if port_text else PEER_DEFAULT_PORT)
            elif choice == "2":
                chat_mode(node)
            elif choice == "3":
                node.master_key = validate_key(ask_key(f"new master key for {node.my_id}"))
                print("Master key updated (an active session is not affected).")
            elif choice == "4":
                name = input("Mode (ecb/cbc): ").strip().lower()
                if name not in ("ecb", "cbc"):
                    print("Unknown mode.")
                else:
                    node.mode = MODE_ECB if name == "ecb" else MODE_CBC
                    print(f"Mode set to {name.upper()}.")
            elif choice == "5":
                show_status(node)
            elif choice == "6":
                node.close_session()
            elif choice == "7":
                return
        except (ProtocolError, OSError, ValueError) as error:
            print(f"Error: {error}")


def main():
    if len(sys.argv) < 3:
        print("usage: python3 node.py <id> <kdc_ip> [kdc_port] [listen_port]")
        return
    my_id = validate_id(sys.argv[1])
    kdc_port = int(sys.argv[3]) if len(sys.argv) > 3 else KDC_DEFAULT_PORT
    listen_port = int(sys.argv[4]) if len(sys.argv) > 4 else PEER_DEFAULT_PORT
    master_key = validate_key(ask_key(f"master key for {my_id}"))
    node = Node(my_id, master_key, (sys.argv[2], kdc_port), listen_port)
    node.start_listener()
    print(f"{my_id} listening on port {node.listen_port}")
    try:
        menu(node)
    except (KeyboardInterrupt, EOFError):
        pass
    node.stop()


if __name__ == "__main__":
    main()