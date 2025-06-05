# Sistema de Chat P2P em Rede Local
## Introdução

Este projeto implementa um sistema de comunicação **peer-to-peer (P2P)** para redes locais, permitindo que usuários troquem mensagens de forma segura e descentralizada. O sistema combina um servidor central (tracker) para autenticação e descoberta de peers com comunicação direta entre clientes, garantindo privacidade através de criptografia RSA.

### Características Principais:
- 🔐 Autenticação segura com criptografia assimétrica
- 👥 Comunicação direta entre usuários (P2P)
- 📦 Troca de mensagens privadas (1:1)
- 🏠 Criação e listagem de salas de grupo
- 🌐 Operação em redes locais sem dependência da internet

## Como Funciona

O sistema opera em dois componentes principais:

1. **Tracker**: Servidor central que:
   - Gerencia autenticação de usuários
   - Mantém registro de peers ativos
   - Lista salas de chat disponíveis
   - Opera como autoridade de confiança para troca de chaves públicas

2. **Peer**: Cliente que:
   - Conecta-se ao tracker para autenticação
   - Descobre outros peers na rede local
   - Estabelece conexões diretas para troca de mensagens
   - Opera como servidor para receber mensagens de outros peers

## Tecnologias Utilizadas
- **Linguagem**: Python 3
- **Bibliotecas**:
  - `cryptography` (criptografia RSA)
  - `socket` (comunicação em rede)
  - `threading` (processamento concorrente)
  - `json` (formatação de mensagens)
- **Protocolos**: TCP com mensagens JSON

## Arquitetura Segura
As comunicações sensíveis (credenciais de login) são protegidas por:
1. Criptografia RSA com chave pública do tracker
2. Armazenamento seguro de senhas (hash + salt)
3. Troca de chaves assimétricas no processo de autenticação

> **Nota**: Este projeto foi desenvolvido para redes locais confiáveis, sem tratamento avançado de NAT ou firewalls

## Como Executar
```bash
# Git clone
git clone https://github.com/arthurfonsecaa/ChatP2P.git

# Instalar dependências
pip install -r requirements.txt

# Executar demonstração
python run.py
