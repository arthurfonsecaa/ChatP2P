# peer.py

import socket
import json
import threading
import base64
import time
import os
import re
import sys
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

class PeerClient:
    def __init__(self, tracker_host='localhost', tracker_port=5000):
        self.username = None
        self.tracker_host = tracker_host
        self.tracker_port = tracker_port
        self.peer_port = 0
        self.running = False
        self.public_key = None
        self.peer_socket = None
        self.running = False

        # controla em qual chat estamos: ('dm', peer) ou ('room', room_name)
        self.current_chat = None

        # Geração de chaves RSA
        self.peer_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.peer_public_key = self.peer_private_key.public_key()
        self.peer_public_key_pem = self.peer_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        self.joined_rooms = {}
        self.dm_history = {}
        self.user_db_file = None

        self.room_file_locks = {}
        self.lock_manager = threading.Lock()

        os.makedirs("room_chats", exist_ok=True)
        os.makedirs("users-dm.chats", exist_ok=True)

    # --- Persistência de Room History ---
    def _get_room_history_path(self, room_name):
        safe_room = re.sub(r'[\W_]+', '', room_name)
        return os.path.join("room_chats", f"room_{safe_room}.json")

    def load_room_history(self, room_name):
        path = self._get_room_history_path(room_name)
        if not os.path.exists(path):
            return []
        with self.lock_manager:
            if room_name not in self.room_file_locks:
                self.room_file_locks[room_name] = threading.Lock()
        with self.room_file_locks[room_name]:
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except:
                return []

    def save_room_history(self, room_name, history):
        path = self._get_room_history_path(room_name)
        with self.lock_manager:
            if room_name not in self.room_file_locks:
                self.room_file_locks[room_name] = threading.Lock()
        with self.room_file_locks[room_name]:
            with open(path, 'w') as f:
                json.dump(history, f, indent=4)

    # --- Persistência de DM History ---
    def _get_dm_path(self, peer):
        a, b = sorted([self.username, peer])
        safe = re.sub(r'[\W_]+', '', f"{a}-{b}_dm.json")
        return os.path.join("users-dm.chats", safe)

    def load_dm_history(self, peer):
        path = self._get_dm_path(peer)
        if not os.path.exists(path):
            return []
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except:
            return []

    def save_dm_history(self, peer, history):
        path = self._get_dm_path(peer)
        with open(path, 'w') as f:
            json.dump(history, f, indent=4)

    # --- Comunicação com o tracker ---
    def send_command(self, command):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.tracker_host, self.tracker_port))
                s.send(json.dumps(command).encode('utf-8'))
                return json.loads(s.recv(4096).decode())
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # --- Recebimento P2P ---
    def handle_peer_connection(self, client_socket, addr):
        try:
            data = client_socket.recv(4096).decode('utf-8')
            if not data:
                return
            m = json.loads(data)
            enc = base64.b64decode(m['message'])
            decrypted = self.peer_private_key.decrypt(
                enc,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()

            ts = datetime.now().strftime('%H:%M:%S-%d/%m/%Y')
            sender = m['from']
            msg_type = m['type']

            if msg_type == "room_message":
                room = m['room']
                hist = self.load_room_history(room)
                hist.append({"sender": sender, "text": decrypted, "ts": ts})
                self.save_room_history(room, hist)
                if self.current_chat != ('room', room):
                    print(f"\n💬 [{room}] [{ts}] {sender}: {decrypted}\n> ", end="", flush=True)
            else:  # direct_message
                peer = sender
                hist = self.load_dm_history(peer)
                hist.append({"sender": sender, "text": decrypted, "ts": ts})
                self.save_dm_history(peer, hist)
                if self.current_chat != ('dm', peer):
                    print(f"\n📩 [DM] [{ts}] {sender}: {decrypted}\n> ", end="", flush=True)

        except Exception:
            pass
        finally:
            client_socket.close()

    def listen_for_peers(self):
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.peer_socket.bind(('0.0.0.0', 0))
        self.peer_port = self.peer_socket.getsockname()[1]
        self.peer_socket.listen(5)
        self.running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while self.running:
            try:
                client, addr = self.peer_socket.accept()
            except OSError:
                break
            threading.Thread(
                target=self.handle_peer_connection,
                args=(client, addr),
                daemon=True
            ).start()

    # --- Envio P2P ---
    def send_p2p_message(self, peer_info, message, msg_type, room_name=None):
        self.send_command({
            "cmd": "STORE_MESSAGE",
            "from": self.username,
            "to": peer_info['username'] if msg_type == "direct_message" else None,
            "room": room_name,
            "message": message
        })

        if 'pubkey' not in peer_info or not peer_info['pubkey']:
            kr = self.send_command({"cmd": "GET_PEER_KEY", "user": peer_info['username']})
            if kr.get("status") == "success":
                peer_info['pubkey'] = kr['pubkey']
            else:
                print(f"Erro ao obter chave de {peer_info['username']}")
                return

        pubkey = serialization.load_pem_public_key(
            peer_info['pubkey'].encode(), backend=default_backend()
        )
        encrypted = pubkey.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        packet = {
            "type": msg_type,
            "from": self.username,
            "message": base64.b64encode(encrypted).decode(),
            "room": room_name
        }
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((peer_info['ip'], peer_info['port']))
            s.sendall(json.dumps(packet).encode('utf-8'))

    # --- Chat “live” definitivamente sem duplicações ---
    def enter_chat_view(self, display_name, history_key, send_fn):
        # contexto
        if history_key.startswith("dm_"):
            peer = history_key.split("_",1)[1]
            self.current_chat = ('dm', peer)
            hist = self.load_dm_history(peer)
        else:
            peer = None
            self.current_chat = ('room', history_key)
            hist = self.load_room_history(history_key)

        def print_all():
            os.system('cls' if os.name=='nt' else 'clear')
            print(f"--- Chat com {display_name} --- (digite '/voltar' para sair)\n")
            for m in hist:
                who = "Você" if m['sender']==self.username else m['sender']
                print(f"[{m['ts']}] {who}: {m['text']}\n")
            print("> ", end="", flush=True)

        # imprime o histórico
        print_all()
        last = len(hist)

        def refresher():
            nonlocal last
            while self.current_chat is not None:
                time.sleep(1)
                kind, key = self.current_chat
                new = (self.load_dm_history(key) if kind=='dm'
                       else self.load_room_history(key))
                # se mudou o tamanho, redesenha tudo
                if len(new) != last:
                    hist[:] = new
                    last = len(new)
                    print_all()

        threading.Thread(target=refresher, daemon=True).start()

        # loop de entrada
        while True:
            line = input("> ")
            if line.strip() == '/voltar':
                self.current_chat = None
                break

            # adiciona localmente e envia
            ts = datetime.now().strftime('%H:%M:%S-%d/%m/%Y')
            hist.append({"sender": self.username, "text": line, "ts": ts})
            last = len(hist)

            send_fn(line)
            # redesenha tudo mostrando apenas UMA vez cada mensagem
            print_all()

        # sai do chat
        self.current_chat = None


    # --- Fluxos principais e menus (sem alterações) ---
    def start(self):
        res = self.send_command({"cmd": "GET_PUBKEY"})
        if res.get("status") != "success":
            print("[!] Falha ao obter chave do tracker.")
            return
        self.public_key = serialization.load_pem_public_key(
            res["pubkey"].encode(), backend=default_backend()
        )
        exit_flag = False
        while not exit_flag:
            if self.username:
                self.main_menu()
            else:
                exit_flag = self.auth_menu()

    def auth_menu(self):
        print("\n=== SISTEMA DE CHAT P2P ===")
        print("1. Login\n2. Registrar\n3. Sair")
        c = input("> ")
        if c == '1':
            self.login_flow()
        elif c == '2':
            self.register_flow()
        elif c == '3':
            print("Saindo...")
            return True
        return False

    def login_flow(self):
        username = input("Username: ")
        password = input("Password: ")

        threading.Thread(target=self.listen_for_peers, daemon=True).start()
        time.sleep(0.2)
        if self.peer_port == 0:
            print("[!] Não foi possível alocar porta.")
            return

        enc = self.public_key.encrypt(
            password.encode(),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        login_data = {
            "cmd": "LOGIN",
            "user": username,
            "password": base64.b64encode(enc).decode(),
            "peer_port": self.peer_port,
            "peer_pubkey": self.peer_public_key_pem
        }
        resp = self.send_command(login_data)
        print("\nResposta do tracker:", resp.get("message"))
        if resp.get("status") == "success":
            self.username = username
        else:
            if self.peer_socket:
                self.peer_socket.close()

    def register_flow(self):
        # 1) Pergunta o nome
        username = input("Escolha um username: ")

        # 2) Verifica existência
        chk = self.send_command({"cmd":"CHECK_USER","user":username})
        if chk.get("status")=="success" and chk.get("exists"):
            print(f"\n[!] Usuário '{username}' já existe. Tente outro.")
            return

        # 3) Só agora pede senha
        password = input("Escolha uma senha: ")
        enc = self.public_key.encrypt(
            password.encode(),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None)
        )
        resp = self.send_command({
            "cmd": "REGISTER",
            "user": username,
            "password": base64.b64encode(enc).decode()
        })
        print("\nResposta:", resp.get("message", ""))

    def main_menu(self):
        print(f"\n--- MENU ({self.username}) ---")
        print("1. Mensagens Diretas (DM)")
        print("2. Minhas Salas")
        print("3. Entrar em uma Sala")
        print("4. Criar uma Sala")
        print("5. Listar todos os peers ativos")
        print("6. Listar todas as salas")
        print("7. Logout")
        choice = input("> ")
        actions = {
            '1': self.direct_message_flow,
            '2': self.my_rooms_flow,
            '3': self.join_room_flow,
            '4': self.create_room_flow,
            '5': self.list_peers,
            '6': self.list_all_rooms,
            '7': self.logout
        }
        actions.get(choice, lambda: print("Opção inválida."))()

    def my_rooms_flow(self):
        if not self.joined_rooms:
            print("\nVocê não está em nenhuma sala.")
            return
        print("\n--- Minhas Salas ---")
        rooms = list(self.joined_rooms.keys())
        for i, r in enumerate(rooms, 1):
            mod = " [Moderador]" if self.joined_rooms[r]['moderator'] == self.username else ""
            print(f"{i}. {r}{mod}")
        try:
            idx = int(input("\nSelecione uma sala (0 para voltar): "))
            if idx > 0:
                rn = rooms[idx-1]
                self.enter_chat_view(rn, rn, lambda m: self.send_room_message(rn, m))
        except:
            print("Seleção inválida.")

    def direct_message_flow(self):
        res = self.send_command({"cmd": "LIST_PEERS"})
        if res.get("status") != "success":
            print("Não foi possível listar os peers.")
            return
        peers = res.get("peers", [])
        if not peers:
            print("\nNenhum peer ativo.")
            return
        print("\n--- Peers Ativos ---")
        for i, p in enumerate(peers, 1):
            print(f"{i}. {p['username']} ({p['ip']}:{p['port']})")
        idx = int(input("\nEscolha peer para DM (0 para voltar): "))
        if idx <= 0 or idx > len(peers):
            return
        peer = peers[idx-1]
        hist = self.load_dm_history(peer['username'])
        print(f"\n--- Chat DM com {peer['username']} ---")
        for m in hist:
            who = "Você" if m['sender'] == self.username else m['sender']
            print(f"[{m['ts']}] {who}: {m['text']}")
        print("\nDigite '/voltar' para sair.\n")
        self.enter_chat_view(peer['username'], f"dm_{peer['username']}", lambda m: self.send_p2p_message(peer, m, "direct_message"))

    def list_peers(self):
        res = self.send_command({"cmd": "LIST_PEERS"})
        if res.get("status") == "success":
            print("\n--- Peers Ativos ---")
            for p in res['peers']:
                print(f"- {p['username']} ({p['ip']}:{p['port']})")
        else:
            print("Erro:", res.get("message", ""))

    def list_all_rooms(self):
        res = self.send_command({"cmd": "LIST_ROOMS"})
        if res.get("status") == "success":
            print("\n--- Salas no Tracker ---")
            for r in res['rooms']:
                tag = "[Privada]" if r['is_private'] else "[Pública]"
                print(f"- {r['name']} {tag} (Mod: {r['moderator']}, Membros: {r['members_count']})")
        else:
            print("Erro:", res.get("message", ""))

    def create_room_flow(self):
        name = input("Nome da sala: ")
        if not name:
            print("Nome não pode ser vazio.")
            return
        priv = input("Sala privada? (s/n): ").lower() == 's'
        pwd = input("Senha: ") if priv else None
        res = self.send_command({
            "cmd": "CREATE_ROOM",
            "room_name": name,
            "user": self.username,
            "password": pwd
        })
        print("Resposta:", res.get("message"))
        if res.get("status") == "success":
            self.joined_rooms[name] = res['room_info']

    def join_room_flow(self):
        res = self.send_command({"cmd": "LIST_ROOMS"})
        if res.get("status") != "success":
            print("Não foi possível listar as salas.")
            return
        print("\n--- Salas Disponíveis ---")
        for r in res['rooms']:
            tag = "[Privada]" if r['is_private'] else "[Pública]"
            print(f"- {r['name']} {tag}")
        name = input("\nDigite o nome da sala para entrar: ")
        if not any(r['name'] == name for r in res['rooms']):
            print("Sala não encontrada.")
            return
        pwd = None
        if next(r for r in res['rooms'] if r['name'] == name)['is_private']:
            pwd = input("Senha: ")
        resp = self.send_command({
            "cmd": "JOIN_ROOM",
            "room_name": name,
            "user": self.username,
            "password": pwd
        })
        print("Resposta:", resp.get("message"))
        if resp.get("status") == "success":
            self.joined_rooms[name] = resp['room_info']

    def logout(self):
        if self.username:
            print("Saindo...")
            self.send_command({"cmd": "LOGOUT", "user": self.username})
            # para o listener
            self.running = False
            try:
                self.peer_socket.close()
            except:
                pass
            self.username = None


    def send_room_message(self, room_name, message):
        resp = self.send_command({"cmd": "GET_ROOM_MEMBERS", "room_name": room_name})
        if resp.get("status") == "success":
            for uname, info in resp["members"].items():
                if uname != self.username and info:
                    self.send_p2p_message(info, message, "room_message", room_name)
        else:
            print(f"Erro ao enviar: {resp.get("message")}")

if __name__ == "__main__":
    client = PeerClient()
    try:
        client.start()
    except KeyboardInterrupt:
        print("\n[!] Saindo...")
        client.logout()
