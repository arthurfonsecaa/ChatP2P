# tracker.py

import socket
import threading
import json
import hashlib
import os
import base64
import time
from datetime import datetime, timedelta
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

        # Gera chave RSA do tracker
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # Estruturas em memória
        self.users = {}
        self.active_peers = {}
        self.rooms = {}       # será carregado de disco
        self.messages = []    # logs cifrados
        self.lock = threading.Lock()
        self.last_activity = {}  # rastreia última atividade por usuário

        # Certifica diretórios
        os.makedirs("users", exist_ok=True)
        os.makedirs("rooms", exist_ok=True)

        # Carrega usuários e salas já salvos
        self.load_users()
        self.load_rooms()
        
        # Inicia thread de verificação de heartbeat
        threading.Thread(target=self.heartbeat_checker, daemon=True).start()

    # Verificador de heartbeat em segundo plano
    def heartbeat_checker(self):
        while True:
            time.sleep(10)  # Verifica a cada 10 segundos
            with self.lock:
                now = datetime.now()
                rooms_to_delete = []

                for room_name, room_info in list(self.rooms.items()):
                    timeout = room_info.get("heartbeat_timeout")
                    if not timeout:
                        continue
                    moderator = room_info["moderator"]
                    # Só aplica heartbeat se moderador NÃO estiver online
                    if moderator in self.active_peers:
                        continue
                    last_active = self.last_activity.get(moderator, datetime.min)
                    # Verifica se moderador está inativo além do tempo permitido
                    if (now - last_active).total_seconds() > timeout:
                        rooms_to_delete.append(room_name)

                # Remove salas expiradas e notifica membros
                for room in rooms_to_delete:
                    room_info = self.rooms[room]

                    # Notifica todos os membros
                    for member in list(room_info["members"]):
                        if member in self.active_peers:
                            peer_info = self.active_peers[member]
                            try:
                                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                s.connect((peer_info["ip"], peer_info["port"]))
                                packet = {
                                    "type": "system",
                                    "message": f"A sala '{room}' foi excluída por inatividade do moderador"
                                }
                                s.send(json.dumps(packet).encode())
                                s.close()
                            except:
                                pass

                    # Remove sala e persiste mudança
                    del self.rooms[room]
                    print(f"[{datetime.now()}] [heartbeat] Sala '{room}' removida por inatividade do moderador")

                if rooms_to_delete:
                    self.save_rooms()


    # Atualiza atividade do usuário
    def update_user_activity(self, user):
        with self.lock:
            self.last_activity[user] = datetime.now()

    # --- Persistência de usuários ---
    def get_users_path(self):
        return os.path.join("users", "users.json")

    def load_users(self):
        path = self.get_users_path()
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    self.users = json.load(f)
                print(f"[*] Carregados {len(self.users)} usuários")
            except Exception as e:
                print(f"Erro ao carregar usuários: {e}")

    def save_users(self):
        try:
            with open(self.get_users_path(), "w") as f:
                json.dump(self.users, f, indent=4)
        except Exception as e:
            print(f"Erro ao salvar usuários: {e}")

    # --- Persistência de salas ---
    def get_rooms_path(self):
        return os.path.join("rooms", "rooms.json")

    def load_rooms(self):
        path = self.get_rooms_path()
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    raw = json.load(f)

                fixed = {}
                now = datetime.now()
                for name, info in raw.items():
                    mod = info.get("moderator")
                    # se faltar 'members', presume só o moderador
                    members_list = info.get("members") or [mod]
                    fixed[name] = {
                        "moderator": mod,
                        "members": set(members_list),
                        "password_hash": info.get("password_hash"),
                        "heartbeat_timeout": info.get("heartbeat_timeout")
                    }
                    # inicializa last_activity do moderador para evitar heartbeat imediato
                    if mod:
                        self.last_activity[mod] = now

                self.rooms = fixed
                print(f"[*] Carregadas {len(self.rooms)} salas")

                # regrava o JSON no disco já convertido (listas em vez de sets)
                self.save_rooms()
            except Exception as e:
                print(f"Erro ao carregar salas: {e}")

    def save_rooms(self):
        try:
            # converte sets em listas para JSON
            data = {
                name: {
                    "moderator": info["moderator"],
                    "members": list(info["members"]),
                    "password_hash": info.get("password_hash"),
                    "heartbeat_timeout": info.get("heartbeat_timeout")
                }
                for name, info in self.rooms.items()
            }
            with open(self.get_rooms_path(), "w") as f:
                json.dump(data, f, indent=4)
        except Exception as e:
            print(f"Erro ao salvar salas: {e}")

    # --- Criptografia de senhas vindas dos peers ---
    def decrypt_password(self, encrypted_b64):
        try:
            encrypted = base64.b64decode(encrypted_b64)
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

    # --- Loop principal de conexão ---
    def handle_client(self, client_socket, addr):
        peer_ip = addr[0]
        print(f"[+] Conexão de {peer_ip}")
        try:
            raw = client_socket.recv(4096).decode()
            if not raw:
                return
            request = json.loads(raw)
            cmd = request.get("cmd", "").upper()

            # Atualiza atividade para todos os comandos autenticados
            if "user" in request:
                self.update_user_activity(request["user"])

            # STORE_MESSAGE trata separadamente
            if cmd == "STORE_MESSAGE":
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
                    "from": request.get("from"),
                    "to": request.get("to"),
                    "room": request.get("room"),
                    "message": base64.b64encode(ciphertext).decode()
                }
                with self.lock:
                    self.messages.append(entry)

                print(f"[{datetime.now()}] REQ(STORE_MESSAGE): {entry}")
                client_socket.send(json.dumps({"status": "success"}).encode())
                return

            # Log genérico
            log_req = copy.deepcopy(request)
            if log_req.get("cmd") == "LOGIN" and "peer_pubkey" in log_req:
                log_req["peer_pubkey"] = "[HIDDEN]"
            print(f"[{datetime.now()}] REQ: {log_req}")

            response = self.process_request(request, peer_ip)

            log_res = copy.deepcopy(response)
            if "pubkey" in log_res:
                log_res["pubkey"] = "[HIDDEN]"
            print(f"[{datetime.now()}] RES: {log_res}")

            client_socket.send(json.dumps(response).encode())
        except Exception as e:
            print(f"Erro no client handler: {e}")
        finally:
            client_socket.close()

    # --- Roteamento de comandos ---
    def process_request(self, req, peer_ip):
        cmd = req.get("cmd", "").upper()
        handlers = {
            "GET_PUBKEY": lambda r: {"status": "success", "pubkey": self.public_key_pem},
            "GET_PEER_KEY": self.handle_get_peer_key,
            "REGISTER": self.handle_register,
            "LOGIN": lambda r: self.handle_login(r, peer_ip),
            "LOGOUT": self.handle_logout,
            "LIST_PEERS": lambda r: self.handle_list_peers(),
            "LIST_ROOMS": lambda r: self.handle_list_rooms(),
            "CREATE_ROOM": self.handle_create_room,
            "JOIN_ROOM": self.handle_join_room,
            "GET_ROOM_MEMBERS": self.handle_get_room_members,
            "CHECK_USER": self.handle_check_user,
            "GET_USER_ROOMS": self.handle_get_user_rooms,
            "GET_ROOM_INFO": self.handle_get_room_info,
            "RENAME_ROOM": self.handle_rename_room,
            "UPDATE_ROOM_PASSWORD": self.handle_update_room_password,
            "SET_ROOM_HEARTBEAT": self.handle_set_room_heartbeat,
            "REMOVE_ROOM_MEMBER": self.handle_remove_room_member,
            "DELETE_ROOM": self.handle_delete_room,
            "GET_ROOM_ALL_MEMBERS": self.handle_get_room_all_members,
        }
        func = handlers.get(cmd)
        if func:
            return func(req)
        return {"status": "error", "message": "Comando inválido"}

    # --- Handlers ---

    def handle_get_room_all_members(self, req):
        room = req.get("room_name")
        info = self.rooms.get(room)
        if not info:
            return {"status": "error", "message": "Sala não encontrada"}
        # devolve TODOS os membros, mesmo os offline
        return {"status": "success", "members": list(info["members"])}

    def handle_rename_room(self, req):
        old = req.get("room_name")
        new = req.get("new_name")
        user = req.get("user")
        if not all([old, new, user]):
            return {"status":"error","message":"Dados incompletos"}
        with self.lock:
            info = self.rooms.get(old)
            if not info:
                return {"status":"error","message":"Sala não existe"}
            if info["moderator"] != user:
                return {"status":"error","message":"Apenas o moderador pode renomear"}
            if new in self.rooms:
                return {"status":"error","message":"Nome já em uso"}
            # efetua renomeação
            self.rooms[new] = info
            del self.rooms[old]
            self.save_rooms()
        # notifica membros
        for m in info["members"]:
            if m in self.active_peers and m != user:
                pi = self.active_peers[m]
                try:
                    s = socket.socket()
                    s.connect((pi["ip"],pi["port"]))
                    s.send(json.dumps({
                        "type":"system",
                        "message":f"A sala '{old}' foi renomeada para '{new}'"
                    }).encode())
                    s.close()
                except: pass
        return {"status":"success","message":f"Sala renomeada para '{new}'"}

    def handle_update_room_password(self, req):
        room = req.get("room_name"); pwd = req.get("new_password"); user = req.get("user")
        if not all([room,pwd,user]):
            return {"status":"error","message":"Dados incompletos"}
        with self.lock:
            info = self.rooms.get(room)
            if not info or info["moderator"]!=user:
                return {"status":"error","message":"Permissão negada"}
            info["password_hash"] = hashlib.sha256(pwd.encode()).hexdigest()
            self.save_rooms()
        return {"status":"success","message":"Senha da sala atualizada"}

    def handle_set_room_heartbeat(self, req):
        room = req.get("room_name"); timeout = req.get("heartbeat_timeout"); user = req.get("user")
        if not all([room,timeout,user]):
            return {"status":"error","message":"Dados incompletos"}
        with self.lock:
            info = self.rooms.get(room)
            if not info or info["moderator"]!=user:
                return {"status":"error","message":"Permissão negada"}
            try:
                t = int(timeout)
                info["heartbeat_timeout"] = t if t>0 else None
            except:
                return {"status":"error","message":"Timeout inválido"}
            self.save_rooms()
        return {"status":"success","message":"Deletar por inatividade atualizado"}

    def handle_remove_room_member(self, req):
        room = req.get("room_name"); target = req.get("target_user"); user = req.get("user")
        if not all([room,target,user]):
            return {"status":"error","message":"Dados incompletos"}
        with self.lock:
            info = self.rooms.get(room)
            if not info or info["moderator"]!=user:
                return {"status":"error","message":"Permissão negada"}
            if target not in info["members"]:
                return {"status":"error","message":"Usuário não está na sala"}
            info["members"].remove(target)
            self.save_rooms()
        # notifica o removido
        if target in self.active_peers:
            pi = self.active_peers[target]
            try:
                s = socket.socket()
                s.connect((pi["ip"],pi["port"]))
                s.send(json.dumps({
                    "type":"system",
                    "message":f"Você foi removido da sala '{room}' pelo moderador"
                }).encode())
                s.close()
            except: pass
        return {"status":"success","message":f"Usuário '{target}' removido"}

    def handle_delete_room(self, req):
        room = req.get("room_name"); user = req.get("user")
        if not all([room,user]):
            return {"status":"error","message":"Dados incompletos"}
        with self.lock:
            info = self.rooms.get(room)
            if not info or info["moderator"]!=user:
                return {"status":"error","message":"Permissão negada"}
            members = list(info["members"])
            del self.rooms[room]
            self.save_rooms()
        # notifica todos
        for m in members:
            if m in self.active_peers and m!=user:
                pi = self.active_peers[m]
                try:
                    s = socket.socket()
                    s.connect((pi["ip"],pi["port"]))
                    s.send(json.dumps({
                        "type":"system",
                        "message":f"A sala '{room}' foi deletada pelo moderador"
                    }).encode())
                    s.close()
                except: pass
        return {"status":"success","message":f"Sala '{room}' deletada"}

    def handle_get_peer_key(self, req):
        user = req.get("user")
        info = self.active_peers.get(user)
        if not info:
            return {"status": "error", "message": "Peer não está online"}
        return {"status": "success", "pubkey": info["pubkey"]}

    def handle_register(self, req):
        user = req.get("user")
        enc = req.get("password")
        if not user or not enc:
            return {"status": "error", "message": "Usuário/senha obrigatórios"}
        if user in self.users:
            return {"status": "error", "message": "Usuário já existe"}
        pwd = self.decrypt_password(enc)
        if not pwd:
            return {"status": "error", "message": "Erro ao decifrar senha"}
        salt = os.urandom(16).hex()
        phash = hashlib.sha256((pwd + salt).encode()).hexdigest()
        with self.lock:
            self.users[user] = {"password_hash": phash, "salt": salt}
            self.save_users()
        return {"status": "success", "message": "Registro bem-sucedido! Você já pode fazer login."}

    def handle_login(self, req, peer_ip):
        user = req.get("user")
        enc = req.get("password")
        port = req.get("peer_port")
        pubk = req.get("peer_pubkey")
        if not all([user, enc, port, pubk]):
            return {"status": "error", "message": "Dados de login incompletos"}
        pwd = self.decrypt_password(enc)
        data = self.users.get(user)
        if not data or not pwd:
            return {"status": "error", "message": "Credenciais inválidas"}
        expected = hashlib.sha256((pwd + data["salt"]).encode()).hexdigest()
        if expected != data["password_hash"]:
            return {"status": "error", "message": "Credenciais inválidas"}
        with self.lock:
            self.active_peers[user] = {"ip": peer_ip, "port": port, "pubkey": pubk}
            self.last_activity[user] = datetime.now()
        return {"status": "success", "message": f"Login bem-sucedido, {user}!"}

    def handle_logout(self, req):
        user = req.get("user")
        with self.lock:
            # apenas removemos o peer ativo; mantemos as salas em que o usuário participa
            if user in self.active_peers:
               del self.active_peers[user]
        return {"status": "success", "message": "Logout efetuado com sucesso!"}

    def handle_list_peers(self):
        return {
            "status": "success",
            "peers": [
                {"username": u, "ip": d["ip"], "port": d["port"]}
                for u, d in self.active_peers.items()
            ]
        }

    def handle_list_rooms(self):
        with self.lock:
            return {
                "status": "success",
                "rooms": [
                    {
                        "name": name,
                        "moderator": info["moderator"],
                        "members_count": len(info["members"]),
                        "is_private": info["password_hash"] is not None
                    }
                    for name, info in self.rooms.items()
                ]
            }
            
    def handle_get_user_rooms(self, req):
        user = req.get("user")
        if not user:
            return {"status": "error", "message": "Usuário não especificado"}
        with self.lock:
            user_rooms = []
            for room_name, room_info in self.rooms.items():
                if user in room_info["members"]:
                    user_rooms.append(room_name)
            return {"status": "success", "rooms": user_rooms}
    
    def handle_get_room_info(self, req):
        room = req.get("room_name")
        info = self.rooms.get(room)
        if not info:
            return {"status": "error", "message": "Sala não encontrada"} 
        return {
            "status": "success", 
            "room_info": {
                "moderator": info["moderator"],
                "is_private": info["password_hash"] is not None
            }
        }

    def handle_create_room(self, req):
        room = req.get("room_name")
        user = req.get("user")
        pwd = req.get("password")
        if not room or not user:
            return {"status": "error", "message": "Dados incompletos"}
        if user not in self.active_peers:
            return {"status": "error", "message": "Usuário não autenticado"}
        with self.lock:
            if room in self.rooms:
                return {"status": "error", "message": "Sala já existe"}
            phash = hashlib.sha256(pwd.encode()).hexdigest() if pwd else None
            
            # heartbeat de inatividade
            heartbeat_timeout = None
            heartbeat = req.get("heartbeat", "").lower()
            if heartbeat == "s":
                try:
                    timeout_sec = int(req.get("heartbeat_timeout", 0))
                    if timeout_sec > 0:
                        heartbeat_timeout = timeout_sec
                except:
                    pass
            
            self.rooms[room] = {
                "moderator": user,
                "members": {user},
                "password_hash": phash,
                "heartbeat_timeout": heartbeat_timeout
            }
            self.save_rooms()
        msg = f"Sala '{room}' criada com sucesso!"
        if pwd:
            msg += " (Privada)"
        return {"status": "success", "message": msg, "room_info": {"moderator": user}}

    def handle_join_room(self, req):
        room = req.get("room_name")
        user = req.get("user")
        pwd = req.get("password")
        if not room or not user:
            return {"status": "error", "message": "Dados incompletos"}
        if user not in self.active_peers:
            return {"status": "error", "message": "Usuário não autenticado"}
        with self.lock:
            info = self.rooms.get(room)
            if not info:
                return {"status": "error", "message": "Sala não existe"}
            if info["password_hash"]:
                # verifica senha
                if not pwd or hashlib.sha256(pwd.encode()).hexdigest() != info["password_hash"]:
                    return {"status": "error", "message": "Senha incorreta"}
            info["members"].add(user)
            self.save_rooms()
        return {"status": "success", "message": f"Você entrou na sala '{room}' com sucesso!", "room_info": {"moderator": info["moderator"]}}

    def handle_get_room_members(self, req):
        room = req.get("room_name")
        info = self.rooms.get(room)
        if not info:
            return {"status": "error", "message": "Sala não encontrada"}
        with self.lock:
            members = {
                u: {"ip": d["ip"], "port": d["port"]}
                for u, d in self.active_peers.items()
                if u in info["members"]
            }
        return {"status": "success", "members": members}

    def handle_check_user(self, req):
        user = req.get("user")
        return {"status": "success", "exists": user in self.users}

    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        print(f"[*] Tracker ouvindo em {self.host}:{self.port}")
        print("[*] Chave pública do Tracker (começa com -----BEGIN PUBLIC KEY-----)")
        try:
            while True:
                client, addr = self.server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[!] Desligando tracker...")
        finally:
            self.server_socket.close()

if __name__ == "__main__":
    TrackerServer().start()