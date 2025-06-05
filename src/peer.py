import socket
import json
import threading
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

class PeerClient:
    def __init__(self, tracker_host='localhost', tracker_port=5000):
        self.username = None
        self.tracker_host = tracker_host
        self.tracker_port = tracker_port
        self.peer_port = 6000
        self.running = False
        self.public_key = None
        
        # Configurar socket para conexões P2P
        self.peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    def get_tracker_public_key(self):
        """Obtém a chave pública do tracker"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.tracker_host, self.tracker_port))
                s.send(json.dumps({"cmd": "GET_PUBKEY"}).encode('utf-8'))
                response = json.loads(s.recv(4096).decode())  # Tamanho maior para a chave
                if response.get("status") == "success":
                    return response["pubkey"]
        except Exception as e:
            print(f"Erro ao obter chave pública: {e}")
        return None
    
    def encrypt_password(self, password):
        """Criptografa a senha usando a chave pública do tracker"""
        if not self.public_key:
            # Obter chave pública se ainda não tiver
            pubkey_pem = self.get_tracker_public_key()
            if not pubkey_pem:
                return None
            self.public_key = serialization.load_pem_public_key(
                pubkey_pem.encode(),
                backend=default_backend()
            )
        
        encrypted = self.public_key.encrypt(
            password.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode()
    
    def connect_to_tracker(self, username, password):
        """Conecta ao tracker com senha criptografada"""
        # Criptografar a senha
        encrypted_password = self.encrypt_password(password)
        if not encrypted_password:
            return {"status": "error", "message": "Falha ao criptografar senha"}
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.tracker_host, self.tracker_port))
                login_data = {
                    "cmd": "LOGIN",
                    "user": username,
                    "password": encrypted_password,
                    "peer_port": self.peer_port
                }
                s.send(json.dumps(login_data).encode('utf-8'))
                return json.loads(s.recv(1024).decode())
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def register_on_tracker(self, username, password):
        """Registra novo usuário com senha criptografada"""
        # Criptografar a senha
        encrypted_password = self.encrypt_password(password)
        if not encrypted_password:
            return {"status": "error", "message": "Falha ao criptografar senha"}
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.tracker_host, self.tracker_port))
                register_data = {
                    "cmd": "REGISTER",
                    "user": username,
                    "password": encrypted_password
                }
                s.send(json.dumps(register_data).encode('utf-8'))
                return json.loads(s.recv(1024).decode())
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def listen_for_peers(self):
        """Ouve conexões de outros peers (P2P)"""
        self.peer_socket.bind(('0.0.0.0', self.peer_port))
        self.peer_socket.listen(5)
        self.running = True
        print(f"[*] Ouvindo conexões P2P na porta {self.peer_port}")
        
        while self.running:
            try:
                client_sock, addr = self.peer_socket.accept()
                threading.Thread(
                    target=self.handle_peer_connection,
                    args=(client_sock, addr)).start()
            except:
                break
    
    def handle_peer_connection(self, client_socket, addr):
        """Processa mensagens de outros peers"""
        try:
            data = client_socket.recv(1024).decode('utf-8')
            if data:
                message = json.loads(data)
                print(f"\n[P2P] Nova mensagem de {addr}:")
                print(f" - Origem: {message.get('from', '')}")
                print(f" - Sala: {message.get('room', '')}")
                print(f" - Mensagem: {message.get('message', '')}\n")
        finally:
            client_socket.close()
    
    def start(self):
        """Inicia o peer com menu principal"""
        # Obter chave pública do tracker
        pubkey = self.get_tracker_public_key()
        if pubkey:
            self.public_key = serialization.load_pem_public_key(
                pubkey.encode(),
                backend=default_backend()
            )
            print("[*] Chave pública do tracker obtida com sucesso")
        else:
            print("[!] Falha ao obter chave pública do tracker")
        
        while True:
            print("\n=== SISTEMA DE CHAT P2P ===")
            print("1. Login")
            print("2. Registrar novo usuário")
            print("3. Sair")
            
            choice = input("> ")
            
            if choice == '1':
                self.login_flow()
            elif choice == '2':
                self.register_flow()
            elif choice == '3':
                print("Saindo...")
                break
    
    def login_flow(self):
        """Fluxo de autenticação de usuário"""
        username = input("Username: ")
        password = input("Password: ")
        
        # Autenticar no tracker
        login_response = self.connect_to_tracker(username, password)
        print("Resposta do tracker:", login_response)
        
        if login_response.get("status") != "success":
            return
        
        self.username = username
        
        # Iniciar thread para conexões P2P
        listener_thread = threading.Thread(target=self.listen_for_peers)
        listener_thread.daemon = True
        listener_thread.start()
        
        # Menu após login
        self.main_menu()
    
    def register_flow(self):
        """Fluxo de registro de novo usuário"""
        username = input("Escolha um username: ")
        password = input("Escolha uma senha: ")
        confirm_password = input("Confirme a senha: ")
        
        if password != confirm_password:
            print("Erro: As senhas não coincidem")
            return
        
        # Registrar no tracker
        register_response = self.register_on_tracker(username, password)
        print("Resposta do tracker:", register_response)
        
        if register_response.get("status") == "success":
            print("Registro bem-sucedido! Você pode fazer login agora.")
    
    def main_menu(self):
        """Menu principal após autenticação"""
        while True:
            print(f"\nBem-vindo(a), {self.username}!")
            print("1. Listar peers ativos")
            print("2. Listar salas")
            print("3. Criar sala")
            print("4. Logout")
            
            choice = input("> ")
            
            if choice == '1':
                self.list_peers()
            elif choice == '2':
                self.list_rooms()
            elif choice == '3':
                room_name = input("Nome da sala: ")
                self.create_room(room_name)
            elif choice == '4':
                self.logout()
                break
    
    def send_command(self, command):
        """Envia comando para o tracker"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.tracker_host, self.tracker_port))
                s.send(json.dumps(command).encode('utf-8'))
                return json.loads(s.recv(1024).decode())
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def list_peers(self):
        response = self.send_command({"cmd": "LIST_PEERS"})
        if response.get("status") == "success":
            print("\nPeers ativos:")
            for peer in response["peers"]:
                print(f" - {peer['username']} ({peer['ip']}:{peer['port']})")
        else:
            print("Erro:", response.get("message", ""))
    
    def list_rooms(self):
        response = self.send_command({"cmd": "LIST_ROOMS"})
        if response.get("status") == "success":
            print("\nSalas disponíveis:")
            for room in response["rooms"]:
                print(f" - {room['name']} ({len(room['members'])} membros)")
        else:
            print("Erro:", response.get("message", ""))
    
    def create_room(self, room_name):
        response = self.send_command({
            "cmd": "CREATE_ROOM",
            "room_name": room_name,
            "user": self.username
        })
        print(response.get("message", ""))
    
    def logout(self):
        if self.username:
            self.send_command({
                "cmd": "LOGOUT",
                "user": self.username
            })
            self.running = False
            self.peer_socket.close()
            self.username = None
            print("Logout realizado com sucesso!")

if __name__ == "__main__":
    peer = PeerClient()
    peer.start()