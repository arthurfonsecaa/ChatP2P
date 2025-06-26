
import socket
import json
import threading
import base64
import time
import os
import re
import sys
import shutil
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
        self.current_chat = None
        self.in_chat_view = False
        self.notification_queue = []
        self.notification_lock = threading.Lock()
        self.last_hist_length = {}

        # Gera chaves RSA
        self.peer_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        self.peer_public_key = self.peer_private_key.public_key()
        self.peer_public_key_pem = self.peer_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        # Salas locais e histórico
        self.joined_rooms = {}
        self.dm_history = {}
        self.room_file_locks = {}
        self.lock_manager = threading.Lock()

        # Pastas
        os.makedirs("room_chats", exist_ok=True)
        os.makedirs("users-dm.chats", exist_ok=True)
        os.makedirs("local_rooms", exist_ok=True)

        self.load_local_rooms()
        threading.Thread(target=self.notification_checker, daemon=True).start()

    # Imprime menu com estilo
    def print_menu(self):
        print("\n" + "="*50)
        print(f"=== CHATP2P - {self.username} ===".center(50))
        print("="*50)
        print(" 1. Mensagens Diretas (DM)")
        print(" 2. Minhas Salas")
        print(" 3. Entrar em uma Sala")
        print(" 4. Criar uma Sala")
        print(" 5. Listar Peers Online")
        print(" 6. Listar Salas Locais")
        print(" 7. Logout")
        print("="*50)
        print("\n> ", end="", flush=True)

    # Paths e persistência
    def _local_rooms_path(self):
        return os.path.join("local_rooms", "rooms.json")

    def load_local_rooms(self):
        path = self._local_rooms_path()
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    self.joined_rooms = json.load(f)
            except:
                self.joined_rooms = {}
        else:
            self.joined_rooms = {}
        # garante histories carregados
        for room in list(self.joined_rooms.keys()):
            self.save_room_history(room, self.load_room_history(room))

    def save_local_rooms(self):
        # grava somente nas salas LOCAIS do peer
        with open(self._local_rooms_path(), 'w') as f:
            json.dump(self.joined_rooms, f, indent=4)

    # Histórico de salas
    def _room_history_path(self, room):
        safe = re.sub(r'[\W_]+', '', room)
        return os.path.join("room_chats", f"room_{safe}.json")

    def load_room_history(self, room):
        path = self._room_history_path(room)
        if not os.path.exists(path):
            return []
        with self.lock_manager:
            self.room_file_locks.setdefault(room, threading.Lock())
        with self.room_file_locks[room]:
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except:
                return []

    def save_room_history(self, room, hist):
        path = self._room_history_path(room)
        with self.lock_manager:
            self.room_file_locks.setdefault(room, threading.Lock())
        with self.room_file_locks[room]:
            with open(path, 'w') as f:
                json.dump(hist, f, indent=4)

    # Histórico de DM
    def _dm_path(self, peer):
        a, b = sorted([self.username, peer])
        safe = re.sub(r'[\W_]+', '', f"{a}-{b}_dm.json")
        return os.path.join("users-dm.chats", safe)

    def load_dm_history(self, peer):
        path = self._dm_path(peer)
        if not os.path.exists(path):
            return []
        try:
            with open(path, 'r') as f:
                return json.load(f)
        except:
            return []

    def save_dm_history(self, peer, hist):
        with open(self._dm_path(peer), 'w') as f:
            json.dump(hist, f, indent=4)
            
    # Remove sala localmente
    def remove_local_room(self, room):
        # Remove da lista de salas
        if room in self.joined_rooms:
            del self.joined_rooms[room]
            self.save_local_rooms()
            
        # Remove histórico
        path = self._room_history_path(room)
        if os.path.exists(path):
            os.remove(path)

    # Comunicação com Tracker
    def send_command(self, cmd):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.tracker_host, self.tracker_port))
            s.send(json.dumps(cmd).encode())
            resp = json.loads(s.recv(4096).decode())
            s.close()
            return resp
        except Exception as e:
            return {"status": "error", "message": str(e)}
        
    def handle_peer_connection(self, sock, addr):
        try:
            data = sock.recv(4096).decode()
            if not data:
                return
            m = json.loads(data)
            
            # Trata mensagens de sistema
            if m.get('type') == "system":
                msg = m.get('message', '')
                print(f"\n\n[ SISTEMA ] {msg}\n")
                # Se é notificação de sala excluída
                if "excluída por inatividade" in msg:
                    room_name = msg.split("'")[1]  # Extrai o nome da sala
                    # Remove a sala localmente E apaga o JSON de chat ASSOCIADO
                    self.remove_local_room(room_name)
                if not self.in_chat_view:
                    self.print_menu()
                return
                
            # Decripta mensagens normais
            decrypted = self.peer_private_key.decrypt(
                base64.b64decode(m['message']),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            ).decode()
            ts = datetime.now().strftime('%H:%M:%S-%d/%m/%Y')
            sender = m['from']
            typ = m['type']

            if typ == "room_message":
                room = m['room']
                hist = self.load_room_history(room)
                entry = {"sender": sender, "text": decrypted, "ts": ts}
                
                # Verifica se a mensagem já existe
                if not any(e['ts'] == ts and e['sender'] == sender and e['text'] == decrypted for e in hist):
                    hist.append(entry)
                    self.save_room_history(room, hist)
                
                # Adiciona à fila de notificações
                with self.notification_lock:
                    self.notification_queue.append((
                        "room", 
                        room, 
                        f"[{room}] {sender}: {decrypted}"
                    ))
            
            else:  # direct_message
                hist = self.load_dm_history(sender)
                entry = {"sender": sender, "text": decrypted, "ts": ts}
                
                # Verifica se a mensagem já existe
                if not any(e['ts'] == ts and e['sender'] == sender and e['text'] == decrypted for e in hist):
                    hist.append(entry)
                    self.save_dm_history(sender, hist)
                
                # Adiciona à fila de notificações
                with self.notification_lock:
                    self.notification_queue.append((
                        "dm", 
                        sender, 
                        f"[DM] {sender}: {decrypted}"
                    ))

        except Exception as e:
            print(f"Erro no handle_peer_connection: {e}")
        finally:
            sock.close()

    # Verificador de notificações em segundo plano
    def notification_checker(self):
        while True:
            time.sleep(1)
            if not self.notification_queue:
                continue
                
            with self.notification_lock:
                notifications = self.notification_queue.copy()
                self.notification_queue = []
                
            for n_type, target, msg in notifications:
                if n_type == "room":
                    if self.current_chat and self.current_chat[0] == 'room' and self.current_chat[1] == target:
                        continue
                    print(f"\n\n{msg}\n")
                    if not self.in_chat_view:
                        self.print_menu()
                else:
                    if self.current_chat and self.current_chat[0] == 'dm' and self.current_chat[1] == target:
                        continue
                    print(f"\n\n{msg}\n")
                    if not self.in_chat_view:
                        self.print_menu()

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
                client, _ = self.peer_socket.accept()
            except OSError:
                break
            threading.Thread(target=self.handle_peer_connection, args=(client, None), daemon=True).start()


    def send_p2p_message(self, peer_info, msg, typ, room=None):
            # Armazena log no tracker
            self.send_command({
                "cmd": "STORE_MESSAGE",
                "from": self.username,
                "to": peer_info.get('username'),
                "room": room,
                "message": msg
            })

            # Busca pubkey se necessário
            if not peer_info.get('pubkey'):
                kr = self.send_command({"cmd": "GET_PEER_KEY", "user": peer_info['username']})
                if kr.get("status") == "success":
                    peer_info['pubkey'] = kr['pubkey']
                else:
                    print(f"Erro ao obter chave de {peer_info['username']}")
                    return

            pub = serialization.load_pem_public_key(
                peer_info['pubkey'].encode(), backend=default_backend()
            )
            enc = pub.encrypt(
                msg.encode(),
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
            packet = {
                "type": typ,
                "from": self.username,
                "message": base64.b64encode(enc).decode(),
                "room": room
            }
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((peer_info['ip'], peer_info['port']))
            s.send(json.dumps(packet).encode())
            s.close()

    def enter_chat_view(self, name, key, send_fn):
        self.in_chat_view = True
        is_dm = key.startswith("dm_")
        
        if is_dm:
            self.current_chat = ('dm', name)
            # Corrigido: usar o nome do usuário como chave para DMs
            cache_key = name
        else:
            self.current_chat = ('room', key)
            cache_key = key

        # Carregar histórico inicial
        hist = self.load_dm_history(name) if is_dm else self.load_room_history(key)
        self.last_hist_length[cache_key] = len(hist)  # Corrigido: usar cache_key consistente

        def draw():
            os.system('cls' if os.name == 'nt' else 'clear')
            print(f"--- Chat com {name} --- (digite '/voltar' para sair)\n")
            for m in hist:
                who = "Você" if m['sender'] == self.username else m['sender']
                print(f"[{m['ts']}] {who}: {m['text']}")
            print("\n> ", end="", flush=True)

        draw()

        def refresher():
            nonlocal hist
            while True:
                time.sleep(1)
                if not self.current_chat:
                    break
                    
                # Carregar novo histórico
                new_hist = self.load_dm_history(name) if is_dm else self.load_room_history(key)
                
                # Verificar se há novas mensagens
                if len(new_hist) > self.last_hist_length[cache_key]:
                    hist = new_hist
                    self.last_hist_length[cache_key] = len(new_hist)
                    
                    # Redesenhar apenas se estiver no chat atual
                    if (self.current_chat[0] == 'dm' and self.current_chat[1] == name) or \
                    (self.current_chat[0] == 'room' and self.current_chat[1] == key):
                        draw()

        threading.Thread(target=refresher, daemon=True).start()

        while True:
            try:
                line = input("> ")
                if not line.strip():
                    continue
                if line.strip() == "/voltar":
                    self.current_chat = None
                    self.in_chat_view = False
                    os.system('cls' if os.name == 'nt' else 'clear')
                    break

                send_fn(line)

                # Atualizar histórico local após envio
                if is_dm:
                    new_hist = self.load_dm_history(name)
                else:
                    new_hist = self.load_room_history(key)
                
                hist = new_hist
                self.last_hist_length[cache_key] = len(new_hist)
                draw()

            except KeyboardInterrupt:
                self.current_chat = None
                self.in_chat_view = False
                break

    # Fluxos principais
    def start(self):
        resp = self.send_command({"cmd": "GET_PUBKEY"})
        if resp.get("status") != "success":
            print("[!] Falha ao obter chave do tracker.")
            return
        self.public_key = serialization.load_pem_public_key(resp["pubkey"].encode(), backend=default_backend())

        while True:
            if not self.username:
                if self.auth_menu():
                    break
            else:
                self.main_menu()

    def auth_menu(self):
        print("\n" + "="*50)
        print("=== SISTEMA DE CHAT P2P ===".center(50))
        print("="*50)
        print(" 1. Login")
        print(" 2. Registrar")
        print(" 3. Sair")
        print("="*50)
        print("\n> ", end="", flush=True)
        
        choice = input().strip()
        if choice == '1':
            self.login_flow()
        elif choice == '2':
            self.register_flow()
        elif choice == '3':
            print("\nSaindo...")
            return True
        else:
            print("\nOpção inválida.")
        return False

    def login_flow(self):
        print("\n" + "-"*50)
        user = input(" Username: ")
        password = input(" Password: ")
        threading.Thread(target=self.listen_for_peers, daemon=True).start()
        time.sleep(0.2)
        if self.peer_port == 0:
            print("\n[!] Falha ao alocar porta.")
            return
            
        enc = self.public_key.encrypt(
            password.encode(),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        resp = self.send_command({
            "cmd": "LOGIN", "user": user,
            "password": base64.b64encode(enc).decode(),
            "peer_port": self.peer_port,
            "peer_pubkey": self.peer_public_key_pem
        })
        print(f"\n{resp.get('message')}\n")
        if resp.get("status") == "success":
            self.username = user
            # sincroniza as salas locais removendo tudo que o tracker já não conhece (heartbeates enquanto você estava offline)
            self.sync_local_rooms()
        else:
            self.peer_socket.close()
        input("\nPressione Enter para continuar...")

    def sync_local_rooms(self):
        """Remove localmente qualquer sala que o tracker já não lista para este usuário."""
        resp = self.send_command({"cmd": "GET_USER_ROOMS", "user": self.username})
        if resp.get("status") != "success":
            return
        servidor = set(resp.get("rooms", []))
        locais = list(self.joined_rooms.keys())
        for room in locais:
            if room not in servidor:
                # Apenas remove a sala da lista local; mantém o histórico intacto
                self.joined_rooms.pop(room, None)
        # garante que o arquivo de salas locais reflita a limpeza
        self.save_local_rooms()

    def register_flow(self):
        print("\n" + "-"*50)
        user = input(" Escolha um username: ")
        chk = self.send_command({"cmd": "CHECK_USER", "user": user})
        if chk.get("status") == "success" and chk.get("exists"):
            print(f"\nUsuário '{user}' já existe.")
            input("\nPressione Enter para continuar...")
            return
            
        password = input(" Escolha uma senha: ")
        enc = self.public_key.encrypt(
            password.encode(),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        resp = self.send_command({
            "cmd": "REGISTER", "user": user,
            "password": base64.b64encode(enc).decode()
        })
        print(f"\n{resp.get('message')}\n")
        input("\nPressione Enter para continuar...")

    def main_menu(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        self.print_menu()
        actions = {
            '1': self.direct_message_flow,
            '2': self.my_rooms_flow,
            '3': self.join_room_flow,
            '4': self.create_room_flow,
            '5': self.list_peers,
            '6': self.list_local_rooms,
            '7': self.logout,
        }
        while True:
            choice = input().strip()
            fn = actions.get(choice)
            if fn:
                fn()
                return
            print("\nOpção inválida. Digite novamente.\n> ", end="", flush=True)

    def my_rooms_flow(self):
        resp = self.send_command({"cmd": "GET_USER_ROOMS", "user": self.username})
        if resp.get("status") != "success":
            print("\nErro ao obter salas do usuário:", resp.get("message"))
            input("\nPressione Enter para voltar...")
            return
            
        user_rooms = resp.get("rooms", [])
        if not user_rooms:
            print("\nVocê não está em nenhuma sala.")
            input("\nPressione Enter para voltar...")
            return
            
        print("\n" + "="*50)
        print("=== MINHAS SALAS ===".center(50))
        print("="*50)
        
        for i, room in enumerate(user_rooms, 1):
            # Verifica se é moderador
            room_info_resp = self.send_command({"cmd": "GET_ROOM_INFO", "room_name": room})
            if room_info_resp.get("status") == "success":
                mod = room_info_resp["room_info"]["moderator"]
                tag = " (Moderador)" if mod == self.username else ""
            else:
                tag = ""
            print(f" {i}. {room}{tag}")
            
        print("="*50)
        print(" 0. Voltar")
        print("="*50)
        print("\n> ", end="", flush=True)
            
        idx = input().strip()
        if not idx.isdigit():
            return
        idx = int(idx)
        if idx <= 0 or idx > len(user_rooms):
            return
            
        selected_room = user_rooms[idx-1]
        # verifica se é moderador
        mod_resp = self.send_command({"cmd":"GET_ROOM_INFO","room_name":selected_room})
        is_mod = (mod_resp.get("status")=="success" and mod_resp["room_info"]["moderator"]==self.username)

        # submenu
        while True:
            os.system('cls' if os.name=='nt' else 'clear')
            print(f"\n=== SALA: {selected_room} ===")
            print(" 1. Chat da Sala")
            if is_mod:
                print(" 2. Gerenciar Sala")
            print(" 0. Voltar")
            choice = input("\n> ").strip()
            if choice=='1':
                return self.enter_chat_view(selected_room, selected_room,
                    lambda m: self.send_room_message(selected_room, m))
            if is_mod and choice=='2':
                return self.manage_room_flow(selected_room)
            if choice=='0':
                return
            print("Opção inválida.")

    def manage_room_flow(self, room):
        while True:
            os.system('cls' if os.name=='nt' else 'clear')
            print(f"\n=== GERENCIAR SALA: {room} ===")
            print(" 1. Trocar nome")
            print(" 2. Alterar senha")
            print(" 3. (Des)ativar exclusão por inatividade")
            print(" 4. Remover membro")
            print(" 5. Deletar sala")
            print(" 0. Voltar")
            choice = input("\nEscolha uma opção: ").strip()
            
            # tenta converter para inteiro
            if not choice.isdigit():
                print("Opção inválida. Digite um número.")
                time.sleep(1)
                continue
            opt = int(choice)

            if opt == 1:
                new = input(" Novo nome: ").strip()
                r = self.send_command({
                    "cmd":"RENAME_ROOM","room_name":room,
                    "new_name":new,"user":self.username
                })
                print(r.get("message"))
                if r.get("status")=="success":
                    # renomeia o histórico
                    hist_old = self._room_history_path(room)
                    hist_new = self._room_history_path(new)
                    if os.path.exists(hist_old):
                        os.rename(hist_old, hist_new)
                    # atualiza joined_rooms de forma segura
                    if room in self.joined_rooms:
                        self.joined_rooms[new] = self.joined_rooms.pop(room)
                    else:
                        self.joined_rooms[new] = {"moderator": self.username}
                    self.save_local_rooms()
                    room = new
                input("Enter para continuar...")

            elif opt == 2:
                pwd = input(" Nova senha (vazio para pública): ")
                r = self.send_command({
                    "cmd":"UPDATE_ROOM_PASSWORD",
                    "room_name":room,
                    "new_password":pwd,
                    "user":self.username
                })
                print(r.get("message"))
                input("Enter para continuar...")

            elif opt == 3:
                # aqui só entra se o usuário digitou "3"
                cur = input(" Tempo inatividade (segundos, 0 p/ desativar): ").strip()
                # valida o número
                if not cur.isdigit():
                    print("Timeout inválido. Use apenas dígitos.")
                    time.sleep(1)
                    continue
                r = self.send_command({
                    "cmd":"SET_ROOM_HEARTBEAT",
                    "room_name":room,
                    "heartbeat_timeout":cur,
                    "user":self.username
                })
                print(r.get("message"))
                input("Enter para continuar...")

            elif opt == 4:
                # lista TODOS os membros (online e offline)
                lm = self.send_command({"cmd":"GET_ROOM_ALL_MEMBERS","room_name":room})
                members = lm.get("members", [])
                if not members:
                    print("Nenhum membro para remover.")
                    input("Enter para continuar...")
                    continue
                for i,u in enumerate(members,1):
                    print(f" {i}. {u}")
                idx = input("Selecionar (0 cancelar): ").strip()
                if not idx.isdigit():
                    print("Opção inválida.")
                    time.sleep(1)
                    continue
                idx = int(idx)
                if idx == 0:
                    continue
                if 1 <= idx <= len(members):
                    tgt = members[idx-1]
                    r = self.send_command({
                        "cmd":"REMOVE_ROOM_MEMBER",
                        "room_name":room,
                        "target_user":tgt,
                        "user":self.username
                    })
                    print(r.get("message"))
                else:
                    print("Opção inválida.")
                input("Enter para continuar...")

            elif opt == 5:
                confirm = input("Confirmar deleção da sala? (s/n): ").lower().strip()
                if confirm == 's':
                    r = self.send_command({
                        "cmd":"DELETE_ROOM",
                        "room_name":room,
                        "user":self.username
                    })
                    print(r.get("message"))
                    if r.get("status")=="success":
                        self.remove_local_room(room)
                        input("Enter para sair...")
                        return
                input("Enter para continuar...")

            elif opt == 0:
                return

            else:
                print("Opção inválida.")
                time.sleep(1)


    def direct_message_flow(self):
        resp = self.send_command({"cmd": "LIST_PEERS"})
        if resp.get("status") != "success":
            print("\nErro ao listar peers.")
            input("\nPressione Enter para voltar...")
            return
            
        peers = resp.get("peers", [])
        if not peers:
            print("\nNenhum peer ativo.")
            input("\nPressione Enter para voltar...")
            return
            
        print("\n" + "="*50)
        print("=== PEERS ATIVOS ===".center(50))
        print("="*50)
        for i, p in enumerate(peers, 1):
            print(f" {i}. {p['username']} ({p['ip']}:{p['port']})")
            
        print("="*50)
        print(" 0. Voltar")
        print("="*50)
        print("\n> ", end="", flush=True)
            
        idx = input().strip()
        if not idx.isdigit():
            return
        idx = int(idx)
        if idx <= 0 or idx > len(peers):
            return
            
        peer = peers[idx - 1]
        hist = self.load_dm_history(peer['username'])
        
        print("\n" + "="*50)
        print(f"=== DM com {peer['username']} ===".center(50))
        print("="*50)
        for m in hist:
            who = "Você" if m['sender'] == self.username else m['sender']
            print(f"  [{m['ts']}] {who}:")
            print(f"  {m['text']}\n")
        print("="*50)
        
        self.enter_chat_view(
            peer['username'], 
            f"dm_{peer['username']}", 
            lambda m: self.send_p2p_message(peer, m, "direct_message")
        )

    def list_peers(self):
        resp = self.send_command({"cmd": "LIST_PEERS"})
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print("\n" + "="*50)
        print("=== PEERS ONLINE ===".center(50))
        print("="*50)
        
        if resp.get("status") == "success":
            for p in resp['peers']:
                print(f" - {p['username']} ({p['ip']}:{p['port']})")
        else:
            print(" Erro:", resp.get("message"))
            
        print("="*50)
        input("\nPressione Enter para voltar...")

    def list_local_rooms(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print("\n" + "="*50)
        print("=== SALAS LOCAIS ===".center(50))
        print("="*50)
        
        if not self.joined_rooms:
            print(" Nenhuma sala local.")
        else:
            for name, info in self.joined_rooms.items():
                mod = info.get('moderator', '')
                print(f" - {name} (Mod: {mod})")
                
        print("="*50)
        input("\nPressione Enter para voltar...")

    def create_room_flow(self):
        print("\n" + "="*50)
        print("=== CRIAR SALA ===".center(50))
        print("="*50)
        
        name = input(" Nome da sala: ").strip()
        if not name:
            print("\nNome vazio.")
            input("\nPressione Enter para voltar...")
            return
            
        priv = input(" Privada? (s/n): ").strip().lower() == 's'
        pwd = input(" Senha: ") if priv else None
        
        # Heartbeat de inatividade
        heartbeat = input(" Habilitar deletar por inatividade? (s/n): ").strip().lower()
        heartbeat_timeout = 0
        if heartbeat == 's':
            try:
                timeout = int(input(" Tempo de inatividade (segundos): "))
                if timeout > 0:
                    heartbeat_timeout = timeout
            except:
                print("\nTempo inválido, deletar por inatividade desabilitado")
        
        cmd = {
            "cmd": "CREATE_ROOM", 
            "room_name": name, 
            "user": self.username, 
            "password": pwd
        }
        
        if heartbeat_timeout:
            cmd["heartbeat"] = "s"
            cmd["heartbeat_timeout"] = heartbeat_timeout
        
        resp = self.send_command(cmd)
        
        print(f"\n{resp.get('message')}")
        if resp.get("status") == "success":
            self.joined_rooms[name] = {"moderator": self.username}
            self.save_room_history(name, [])
            self.save_local_rooms()
            if heartbeat_timeout:
                print(f"\nDeletar por inatividade habilitado: Sala será excluída após {heartbeat_timeout} segundos de inatividade")
        else:
            print("\nFalha ao criar sala.")
            
        input("\nPressione Enter para continuar...")

    def join_room_flow(self):
        resp = self.send_command({"cmd": "LIST_ROOMS"})
        if resp.get("status") != "success":
            print("\nErro ao listar salas.")
            input("\nPressione Enter para voltar...")
            return
            
        rooms = resp.get("rooms", [])
        if not rooms:
            print("\nNenhuma sala disponível no tracker.")
            input("\nPressione Enter para voltar...")
            return

        # Filtra apenas salas que o usuário ainda não está
        available_rooms = [r for r in rooms if r['name'] not in self.joined_rooms]
        
        if not available_rooms:
            print("\nVocê já está em todas as salas disponíveis.")
            input("\nPressione Enter para voltar...")
            return
            
        print("\n" + "="*50)
        print("=== SALAS DISPONÍVEIS ===".center(50))
        print("="*50)
        for i, room in enumerate(available_rooms, 1):
            tag = "[PRIVADA]" if room['is_private'] else "[PÚBLICA]"
            print(f" {i}. {room['name']} {tag}")
            print(f"    Moderador: {room['moderator']} | Membros: {room['members_count']}\n")
            
        print("="*50)
        print(" 0. Voltar")
        print("="*50)
        print("\n> ", end="", flush=True)
        
        idx = input().strip()
        if not idx.isdigit():
            return
        idx = int(idx)
        if idx <= 0 or idx > len(available_rooms):
            return
            
        sel = available_rooms[idx - 1]
        pwd = None
        if sel['is_private']:
            pwd = input("\n Senha: ")
            
        resp2 = self.send_command({
            "cmd": "JOIN_ROOM",
            "room_name": sel['name'],
            "user": self.username,
            "password": pwd
        })
        
        print(f"\n{resp2.get('message')}")
        
        if resp2.get("status") == "success":
            # Adiciona localmente sem apagar o histórico existente
            self.joined_rooms[sel['name']] = resp2['room_info']
            # Não sobrescreve room_chats/room_<nome>.json aqui!
            self.save_local_rooms()
        else:
            print("\nFalha ao entrar na sala.")
            
        input("\nPressione Enter para continuar...")

    def send_room_message(self, room, msg):
        ts = datetime.now().strftime('%H:%M:%S-%d/%m/%Y')
        hist = self.load_room_history(room)
        
        # Verifica duplicação
        if not any(m['ts'] == ts and m['sender'] == self.username and m['text'] == msg for m in hist):
            hist.append({"sender": self.username, "text": msg, "ts": ts})
            self.save_room_history(room, hist)

        resp = self.send_command({"cmd": "GET_ROOM_MEMBERS", "room_name": room})
        if resp.get("status") != "success":
            print("\nErro ao enviar:", resp.get("message"))
            return

        for u, info in resp["members"].items():
            if u == self.username:
                continue
            peer_info = {
                "username": u,
                "ip": info["ip"],
                "port": info["port"]
            }
            self.send_p2p_message(peer_info, msg, "room_message", room)

    def logout(self):
        if self.username:
            resp = self.send_command({"cmd": "LOGOUT", "user": self.username})
            print(f"\n{resp.get('message')}\n")
            self.running = False
            try:
                self.peer_socket.close()
            except:
                pass
            self.username = None
            input("\nPressione Enter para continuar...")

if __name__ == "__main__":
    client = PeerClient()
    try:
        client.start()
    except KeyboardInterrupt:
        print("\nSaindo...")
        client.logout()