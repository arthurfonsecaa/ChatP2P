
# Sistema de Chat P2P em Rede Local

## Introdução

Este projeto implementa um sistema de comunicação **peer-to-peer (P2P)** para redes locais, unindo:

1. **Tracker (servidor central)**: gerencia autenticação, descoberta de peers e controle de salas.
2. **Peer (cliente P2P)**: conecta-se ao tracker para login, depois troca mensagens diretamente com outros peers.

A comunicação é protegida por criptografia RSA, garantindo sigilo de credenciais e mensagens.

## Funcionalidades

- 🔐 **Registro/Login** com RSA (criptografia OAEP) e armazenamento de senha (`hash + salt`).
- 👥 **Peers ativos**: listagem e descoberta na rede local.
- ✉️ **Mensagens diretas (DM)** 1:1, com histórico salvo em `users-dm.chats/`.
- 🏠 **Salas de grupo**:
  - Criação (pública/privada) e listagem global (tracker) e local (peer).
  - Associação de membros com persistência em `rooms/rooms.json` (tracker) e `local_rooms/rooms.json` (peer).
  - **Heartbeat**: exclusão automática por inatividade do moderador (configurável).
  - **Gerenciamento** (apenas moderador):
    1. Renomear sala (move histórico em `room_chats/`).
    2. Alterar senha.
    3. (Des)ativar exclusão por inatividade.
    4. Remover membro (online ou offline).
    5. Deletar sala.
- 📜 **Histórico de chats**:
  - **Salas** em `room_chats/room_<nome>.json`.
  - **DMs** em `users-dm.chats/<usuário>-<outro>.json`.
  - Histórico preservado ao entrar/sair e renomear salas.

## Estrutura de Pastas

```text
├── tracker.py              # servidor central (tracker)
├── peer.py                 # cliente peer-to-peer
├── requirements.txt        # dependências Python
├── rooms/                  # dados globais de salas (tracker)
│   └── rooms.json
├── local_rooms/            # salas associadas localmente (peer)
│   └── rooms.json
├── room_chats/             # histórico de salas (peer)
│   └── room_<nome>.json
└── users-dm.chats/         # histórico de DMs (peer)
    └── <usuário>-<outro>.json
```

## Instalação

### Clonar repositório
```bash
git clone https://github.com/arthurfonsecaa/ChatP2P.git
```
cd ChatP2P

### Criar e ativar ambiente virtual (opcional)
```bash
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows
```

### Instalar dependências
```bash
pip install -r requirements.txt
```

### Rodar
```bash
python run.py
```

## Uso

### Iniciar o Tracker
```bash
python tracker.py
```
- Escuta na porta 5000 por padrão.

- Gera par de chaves RSA na primeira execução.

- Persiste usuários em users/users.json e salas em rooms/rooms.json.

### Iniciar um Peer
```bash
python peer.py --tracker-host=<IP_DO_TRACKER> --tracker-port=5000
```

- Login/Registro: menu inicial.

### Iniciar automaticamente 1 tracker + 4 peers

```bash
python run.py
```

### Menus:

- Mensagens Diretas (DM): listar peers online e iniciar chat.

- Minhas Salas: listar salas associadas; opção extra “Gerenciar Sala” se for moderador.

- Entrar/Criar Sala.

- Listar Peers Online e Listar Salas Locais.

- Logout: encerra o socket e retorna ao menu de autenticação.


## Considerações Finais
- Desenvolvido para redes locais confiáveis.

- Arquitetura híbrida: tracker para descoberta + peers para troca direta.

- Pode servir de base para sistemas P2P seguros e customizáveis.