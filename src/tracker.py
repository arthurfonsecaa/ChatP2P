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

class TrackerServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Gerar par de chaves RSA
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Estruturas de dados
        self.users = {}  # {username: {'password_hash': hash, 'salt': salt}}
        self.active_peers = {}  # {username: (ip, port)}
        self.rooms = {}  # {room_name: set(members)}
        
        # Lock para operações thread-safe
        self.lock = threading.Lock()
        
        # Carregar usuários existentes
        self.load_users()
    
    def get_users_path(self):
        """Retorna o caminho completo para users.json na mesma pasta do script"""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        return os.path.join(script_dir, "users.json")
    
    def load_users(self):
        """Carrega usuários de um arquivo JSON"""
        try:
            users_file = self.get_users_path()
            if os.path.exists(users_file):
                with open(users_file, "r") as f:
                    self.users = json.load(f)
                print(f"[*] Carregados {len(self.users)} usuários")
        except Exception as e:
            print(f"Erro ao carregar usuários: {e}")
    
    def save_users(self):
        """Salva usuários em um arquivo JSON"""
        try:
            users_file = self.get_users_path()
            with open(users_file, "w") as f:
                json.dump(self.users, f)
        except Exception as e:
            print(f"Erro ao salvar usuários: {e}")
    
    def register_user(self, username, password):
        """Registra um novo usuário com senha hasheada e salt único"""
        if username in self.users:
            return False, "Usuário já existe"
        
        # Gerar salt único
        salt = os.urandom(16).hex()
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        
        with self.lock:
            self.users[username] = {
                'password_hash': password_hash,
                'salt': salt
            }
            self.save_users()
        
        return True, "Registro bem-sucedido"
    
    def authenticate(self, username, password):
        """Verifica as credenciais do usuário"""
        if username not in self.users:
            return False
        
        user_data = self.users[username]
        salt = user_data['salt']
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        
        return user_data['password_hash'] == password_hash
    
    def decrypt_password(self, encrypted_password_b64):
        """Descriptografa a senha usando a chave privada"""
        try:
            encrypted_password = base64.b64decode(encrypted_password_b64)
            decrypted_password = self.private_key.decrypt(
                encrypted_password,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted_password.decode()
        except Exception as e:
            print(f"Erro ao descriptografar senha: {e}")
            return None
    
    def handle_client(self, client_socket, addr):
        """Processa requisições de um peer"""
        peer_ip = addr[0]
        print(f"[+] Conexão estabelecida com {peer_ip}")
        
        try:
            while True:
                data = client_socket.recv(4096).decode('utf-8')  # Aumentado para 4096 para chaves
                if not data:
                    break
                
                try:
                    request = json.loads(data)
                    print(f"[{datetime.now()}] REQ: {request}")
                    
                    # Tratar comando GET_PUBKEY separadamente
                    if request.get("cmd") == "GET_PUBKEY":
                        response = {"status": "success", "pubkey": self.public_key_pem}
                        client_socket.send(json.dumps(response).encode('utf-8'))
                        continue
                    
                    response = self.process_request(request, peer_ip)
                except json.JSONDecodeError:
                    response = {"status": "error", "message": "JSON inválido"}
                
                client_socket.send(json.dumps(response).encode('utf-8'))
                print(f"[{datetime.now()}] RES: {response}")
        
        except ConnectionResetError:
            print(f"[-] Conexão perdida com {peer_ip}")
        finally:
            client_socket.close()
    
    def process_request(self, request, peer_ip):
        """Processa comandos recebidos dos peers"""
        cmd = request.get("cmd", "").upper()
        
        if cmd == "LOGIN":
            return self.handle_login(request, peer_ip)
        elif cmd == "LOGOUT":
            return self.handle_logout(request)
        elif cmd == "LIST_PEERS":
            return self.handle_list_peers()
        elif cmd == "LIST_ROOMS":
            return self.handle_list_rooms()
        elif cmd == "CREATE_ROOM":
            return self.handle_create_room(request)
        elif cmd == "REGISTER":
            return self.handle_register(request)
        elif cmd == "CHECK_USER":
            return self.handle_check_user(request)
        else:
            return {"status": "error", "message": "Comando inválido"}
        
    def handle_check_user(self, request):
        """Verifica se um nome de usuário já existe"""
        username = request.get("user", "")
        
        if not username:
            return {"status": "error", "message": "Nome de usuário faltando"}
        
        exists = username in self.users
        return {"status": "success", "exists": exists}

    def handle_register(self, request):
        """Processa registro de novo usuário com senha criptografada"""
        username = request.get("user", "")
        encrypted_password_b64 = request.get("password", "")
        
        if not username or not encrypted_password_b64:
            return {"status": "error", "message": "Usuário e senha são obrigatórios"}
        
        # Descriptografar a senha
        password = self.decrypt_password(encrypted_password_b64)
        if password is None:
            return {"status": "error", "message": "Falha ao descriptografar senha"}
        
        success, message = self.register_user(username, password)
        if success:
            return {"status": "success", "message": message}
        else:
            return {"status": "error", "message": message}
    
    def handle_login(self, request, peer_ip):
        """Processa login com senha criptografada"""
        username = request.get("user", "")
        encrypted_password_b64 = request.get("password", "")
        
        if not username or not encrypted_password_b64:
            return {"status": "error", "message": "Credenciais faltando"}
        
        # Descriptografar a senha
        password = self.decrypt_password(encrypted_password_b64)
        if password is None:
            return {"status": "error", "message": "Falha ao descriptografar senha"}
        
        if not self.authenticate(username, password):
            return {"status": "error", "message": "Credenciais inválidas"}
        
        with self.lock:
            self.active_peers[username] = (peer_ip, request["peer_port"])
        
        return {"status": "success", "message": "Login realizado"}
    
    def handle_logout(self, request):
        username = request.get("user", "")
        
        with self.lock:
            if username in self.active_peers:
                del self.active_peers[username]
                # Remover usuário de todas as salas
                for room in self.rooms.values():
                    if username in room:
                        room.remove(username)
        
        return {"status": "success", "message": "Logout realizado"}
    
    def handle_list_peers(self):
        return {
            "status": "success",
            "peers": [
                {
                    "username": user,
                    "ip": details[0],
                    "port": details[1]
                } for user, details in self.active_peers.items()
            ]
        }
    
    def handle_list_rooms(self):
        return {
            "status": "success",
            "rooms": [
                {
                    "name": name,
                    "members": list(members)
                } for name, members in self.rooms.items()
            ]
        }
    
    def handle_create_room(self, request):
        room_name = request.get("room_name", "")
        username = request.get("user", "")
        
        if not room_name:
            return {"status": "error", "message": "Nome da sala faltando"}
        
        if username not in self.active_peers:
            return {"status": "error", "message": "Usuário não logado"}
        
        with self.lock:
            if room_name in self.rooms:
                return {"status": "error", "message": "Sala já existe"}
            
            self.rooms[room_name] = set([username])
        
        return {"status": "success", "message": f"Sala '{room_name}' criada"}
    
    def start(self):
        """Inicia o servidor tracker"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"[*] Tracker ouvindo em {self.host}:{self.port}")
        print(f"[*] Chave pública:\n{self.public_key_pem}")
        
        try:
            while True:
                client_socket, addr = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr)
                )
                client_thread.daemon = True
                client_thread.start()
                print(f"[+] Conexões ativas: {threading.active_count() - 1}")
        except KeyboardInterrupt:
            print("\n[!] Desligando tracker...")
        finally:
            self.server_socket.close()

if __name__ == "__main__":
    tracker = TrackerServer()
    tracker.start()