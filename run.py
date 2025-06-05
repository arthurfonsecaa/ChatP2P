import os
import platform
import subprocess
import time

def open_terminal(command, title, working_dir=None):
    """Abre um novo terminal com o comando especificado"""
    system = platform.system()
    cwd = working_dir if working_dir else os.getcwd()
    
    if system == "Windows":
        full_cmd = f'cd /d "{cwd}" && {command}'
        subprocess.Popen(
            f'start cmd /k "title {title} && {full_cmd}"',
            shell=True
        )
    elif system == "Linux":
        full_cmd = f'cd "{cwd}" && {command}'
        subprocess.Popen(
            f'gnome-terminal --title="{title}" -- bash -c "{full_cmd}; exec bash"',
            shell=True
        )
    elif system == "Darwin":  # macOS
        full_cmd = f'cd "{cwd}" && {command}'
        subprocess.Popen(
            f'''osascript -e 'tell application "Terminal" to do script "cd \\"{cwd}\\" && {command}"' -e 'tell application "Terminal" to set custom title of front window to \\"{title}\\""' ''',
            shell=True
        )
    else:
        print(f"Sistema operacional não suportado: {system}")
        return False
    return True

def main():
    print("🚀 Iniciando demonstração do sistema P2P...")
    
    # Obter caminho absoluto da pasta src
    src_dir = os.path.join(os.getcwd(), "src")
    
    # Comandos para cada componente
    python_cmd = "python" if platform.system() == "Windows" else "python3"
    tracker_cmd = f"{python_cmd} tracker.py"
    peer_cmd = f"{python_cmd} peer.py"
    
    # Abrir tracker em novo terminal (na pasta src)
    print("\n🔧 Iniciando tracker...")
    if not open_terminal(tracker_cmd, "TRACKER", src_dir):
        return
    
    time.sleep(2)  # Esperar inicialização
    
    # Abrir peers em terminais separados (também na pasta src)
    for i in range(1, 3):
        print(f"👥 Iniciando peer {i}...")
        open_terminal(peer_cmd, f"PEER {i}", src_dir)
        time.sleep(0.5)
    
    print("\n✅ Demonstração iniciada em 3 terminais separados!")
    print("   - TRACKER: Autenticação e gerenciamento")
    print("   - PEER 1 & PEER 2: Clientes para teste")

if __name__ == "__main__":
    main()