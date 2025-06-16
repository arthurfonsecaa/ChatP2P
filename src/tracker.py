# tracker.py

import socket
import threading
import json
import hashlib
import os
import base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
import copy

class TrackerServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # gera chave RSA do tracker
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        self.users = {}
        self.active_peers = {}
        self.rooms = {}
        self.messages = []   # logs cifrados
        self.lock = threading.Lock()
        
        # garante pasta users
        os.makedirs("users", exist_ok=True)
        self.load_users()

    def get_users_path(self):
        return os.path.join("users", "users.json")

    def load_users(self):
        try:
            path = self.get_users_path()
            if os.path.exists(path):
                with open(path, "r") as f:
                    self.users = json.load(f)
                print(f"[*] Carregados {len(self.users)} usuários")
        except Exception as e:
            print(f"Erro ao carregar usuários: {e}")

    def save_users(self):
        try:
            path = self.get_users_path()
            with open(path, "w") as f:
                json.dump(self.users, f, indent=4)
        except Exception as e:
            print(f"Erro ao salvar usuários: {e}")

    def decrypt_password(self, encrypted_password_b64):
        try:
            encrypted = base64.b64decode(encrypted_password_b64)
            return self.private_key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).decode()
        except Exception:
            return None

    def handle_client(self, client_socket, addr):
        peer_ip = addr[0]
        print(f"[+] Conexão estabelecida com {peer_ip}")

        try:
            data = client_socket.recv(4096).decode('utf-8')
            if not data:
                return

            request = json.loads(data)
            cmd = request.get("cmd", "").upper()

            if cmd == "STORE_MESSAGE":
                # Cifra aqui e armazena em messages
                plaintext = request.get("message", "")
                ciphertext = self.public_key.encrypt(
                    plaintext.encode(),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                entry = {
                    "timestamp": datetime.now().isoformat(),
                    "from":    request.get("from"),
                    "to":      request.get("to"),
                    "room":    request.get("room"),
                    "message": base64.b64encode(ciphertext).decode()
                }
                with self.lock:
                    self.messages.append(entry)

                # Log único: REQ com a message já cifrada
                log_req = {
                    "cmd": "STORE_MESSAGE",
                    "from": entry["from"],
                    "to": entry["to"],
                    "room": entry["room"],
                    "message": entry["message"]
                }
                print(f"[{datetime.now()}] REQ: {log_req}")
                
                # Responde diretamente
                response = {"status": "success"}
                client_socket.send(json.dumps(response).encode('utf-8'))
                return

            # Para outros comandos, log normal de REQ
            log_request = copy.deepcopy(request)
            if log_request.get("cmd") == "LOGIN" and 'peer_pubkey' in log_request:
                log_request['peer_pubkey'] = '[CHAVE PÚBLICA OCULTA]'
            print(f"[{datetime.now()}] REQ: {log_request}")

            response = self.process_request(request, peer_ip)

            log_response = copy.deepcopy(response)
            if 'pubkey' in log_response:
                log_response['pubkey'] = '[CHAVE PÚBLICA OCULTA]'
            print(f"[{datetime.now()}] RES: {log_response}")

            client_socket.send(json.dumps(response).encode('utf-8'))

        except (ConnectionResetError, json.JSONDecodeError):
            print(f"[-] Conexão perdida com {peer_ip}")
        finally:
            client_socket.close()

    def handle_store_message(self, request):
        # agora apenas um stub; toda a lógica de cifrar e armazenar
        # foi movida para handle_client
        return {"status": "success"}


    def process_request(self, request, peer_ip):
        cmd = request.get("cmd", "").upper()
        handlers = {
            "GET_PUBKEY": lambda r: {"status": "success", "pubkey": self.public_key_pem},
            "GET_PEER_KEY":      self.handle_get_peer_key, 
            "REGISTER": lambda r: self.handle_register(r),
            "LOGIN":    lambda r: self.handle_login(r, peer_ip),
            "LOGOUT":   lambda r: self.handle_logout(r),
            "LIST_PEERS": lambda r: self.handle_list_peers(),
            "LIST_ROOMS": lambda r: self.handle_list_rooms(),
            "CREATE_ROOM": lambda r: self.handle_create_room(r),
            "JOIN_ROOM":   lambda r: self.handle_join_room(r),
            "GET_ROOM_MEMBERS": lambda r: self.handle_get_room_members(r),
            "STORE_MESSAGE": lambda r: self.handle_store_message(r),
            "CHECK_USER":   self.handle_check_user,
        }
        handler = handlers.get(cmd)
        if handler:
            return handler(request)
        return {"status": "error", "message": "Comando inválido"}
    
    def handle_get_peer_key(self, request):
        target = request.get("user")
        info = self.active_peers.get(target)
        if not info:
            return {"status": "error", "message": f"Peer '{target}' não está online"}
        return {"status": "success", "pubkey": info["pubkey"]}

    def handle_register(self, request):
        username = request.get("user")
        enc = request.get("password")
        if not username or not enc:
            return {"status": "error", "message": "Usuário e senha são obrigatórios"}
        if username in self.users:
            return {"status": "error", "message": "Usuário já existe"}
        password = self.decrypt_password(enc)
        if not password:
            return {"status": "error", "message": "Falha ao processar senha"}
        salt = os.urandom(16).hex()
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        with self.lock:
            self.users[username] = {"password_hash": password_hash, "salt": salt}
            self.save_users()
        return {"status": "success", "message": "Registro bem-sucedido"}

    def handle_login(self, request, peer_ip):
        username = request.get("user")
        enc = request.get("password")
        peer_port = request.get("peer_port")
        peer_pubkey = request.get("peer_pubkey")
        if not all([username, enc, peer_port, peer_pubkey]):
            return {"status": "error", "message": "Dados de login incompletos"}
        password = self.decrypt_password(enc)
        user_data = self.users.get(username)
        if not user_data or not password:
            return {"status": "error", "message": "Credenciais inválidas"}
        expected = hashlib.sha256((password + user_data['salt']).encode()).hexdigest()
        if user_data['password_hash'] != expected:
            return {"status": "error", "message": "Credenciais inválidas"}
        with self.lock:
            self.active_peers[username] = {
                "ip": peer_ip, "port": peer_port, "pubkey": peer_pubkey
            }
        return {"status": "success", "message": f"Login bem-sucedido, {username}!"}

    def handle_logout(self, request):
        username = request.get("user")
        with self.lock:
            self.active_peers.pop(username, None)
            for room in self.rooms.values():
                room['members'].discard(username)
        return {"status": "success", "message": "Logout realizado"}

    def handle_list_peers(self):
        return {"status": "success", "peers": [
            {"username": u, "ip": d["ip"], "port": d["port"]}
            for u, d in self.active_peers.items()
        ]}

    def handle_list_rooms(self):
        with self.lock:
            return {"status": "success", "rooms": [
                {
                    "name": n,
                    "moderator": d["moderator"],
                    "members_count": len(d["members"]),
                    "is_private": d["password_hash"] is not None
                }
                for n, d in self.rooms.items()
            ]}

    def handle_create_room(self, request):
        room_name = request.get("room_name")
        username = request.get("user")
        pwd = request.get("password")
        if not room_name or not username:
            return {"status": "error", "message": "Dados incompletos"}
        if username not in self.active_peers:
            return {"status": "error", "message": "Usuário não autenticado"}
        with self.lock:
            if room_name in self.rooms:
                return {"status": "error", "message": "Sala com este nome já existe"}
            password_hash = hashlib.sha256(pwd.encode()).hexdigest() if pwd else None
            self.rooms[room_name] = {
                "moderator": username,
                "members": {username},
                "password_hash": password_hash
            }
        msg = f"Sala '{room_name}' criada com sucesso!" + (" (Privada)" if pwd else " (Pública)")
        return {"status": "success", "message": msg, "room_info": {"moderator": username}}

    def handle_join_room(self, request):
        room_name = request.get("room_name")
        username = request.get("user")
        pwd = request.get("password")
        if not room_name or not username:
            return {"status": "error", "message": "Dados incompletos"}
        if username not in self.active_peers:
            return {"status": "error", "message": "Usuário não autenticado"}
        with self.lock:
            room = self.rooms.get(room_name)
            if not room:
                return {"status": "error", "message": "Sala não existe"}
            if room['password_hash']:
                if not pwd or hashlib.sha256(pwd.encode()).hexdigest() != room['password_hash']:
                    return {"status": "error", "message": "Senha incorreta ou não fornecida"}
            room['members'].add(username)
        return {"status": "success", "message": f"Você entrou na sala '{room_name}'", "room_info": {"moderator": room['moderator']}}

    def handle_get_room_members(self, request):
        room_name = request.get("room_name")
        room = self.rooms.get(room_name)
        if not room:
            return {"status": "error", "message": "Sala não encontrada"}
        with self.lock:
            members = {
                user: {"ip": info["ip"], "port": info["port"]}
                for user, info in self.active_peers.items()
                if user in room["members"]
            }
        return {"status": "success", "members": members}

    def handle_check_user(self, request):
        username = request.get("user")
        exists = username in self.users
        return {"status":"success","exists": exists}

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        print(f"[*] Tracker ouvindo em {self.host}:{self.port}")
        print(f"[*] Chave pública do Tracker (inicia com -----BEGIN PUBLIC KEY-----)")
        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr),
                    daemon=True
                ).start()
        except KeyboardInterrupt:
            print("\n[!] Desligando tracker...")
        finally:
            self.server_socket.close()

if __name__ == "__main__":
    tracker = TrackerServer()
    tracker.start()

