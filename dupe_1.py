# launcher.py
import threading
import time
import signal
import utils
import random
from termcolor import colored
from utils import client, directory_authority, node
import sys
import utils.socket_tool
import subprocess

def clear_screen():
    """Clear the console screen"""
    print("\033[2J\033[H", end='')

def print_header():
    """Print the application header"""
    clear_screen()
    print(colored("=" * 60, 'yellow'))
    print(colored("                TOR Network Simulator", 'yellow', attrs=['bold']))
    print(colored("=" * 60, 'yellow'))

def run_directory_authority():
    directory_authority.main()

def run_node(port, is_exit=False):
    node.main(port=port, is_exit=is_exit)

def run_client():
    client.main()

def main():
    print_header()
    
    # Configuration
    num_relays = 3
    num_exits = 2
    dir_auth_port = 12345

    try:
        # Start Directory Authority
        print(colored("\nStarting Directory Authority...", 'yellow'))
        da_thread = threading.Thread(target=run_directory_authority)
        da_thread.daemon = True
        da_thread.start()
        time.sleep(1)

        # Generate random ports for nodes
        port_range = list(range(7000, 9000))
        ports = random.sample(port_range, num_relays + num_exits)

        # Start Relay Nodes in separate terminal windows
        relay_processes = []
        for i, port in enumerate(ports[:num_relays]):
            print(colored(f"\nStarting Relay Node {i+1} on port {port}...", 'blue'))
            
            # For Windows
            if sys.platform == 'win32':
                cmd = f'start cmd /K python -c "from utils.node import main; main({port}, False)"'
                subprocess.Popen(cmd, shell=True)
            # For Unix-like systems (Linux/Mac)
            else:
                cmd = f'gnome-terminal --title="Relay Node {port}" -- python3 -c "from utils.node import main; main({port}, False)"'
                subprocess.Popen(cmd, shell=True)
            
            time.sleep(1)

        # Start Exit Nodes in separate terminal windows
        for i, port in enumerate(ports[-num_exits:]):
            print(colored(f"\nStarting Exit Node {i+1} on port {port}...", 'green'))
            
            # For Windows
            if sys.platform == 'win32':
                cmd = f'start cmd /K python -c "from utils.node import main; main({port}, True)"'
                subprocess.Popen(cmd, shell=True)
            # For Unix-like systems (Linux/Mac)
            else:
                cmd = f'gnome-terminal --title="Exit Node {port}" -- python3 -c "from utils.node import main; main({port}, True)"'
                subprocess.Popen(cmd, shell=True)
            
            time.sleep(1)

        print(colored("\nNetwork setup complete!", 'yellow', attrs=['bold']))
        print(colored("\nNode Summary:", 'white', attrs=['bold']))
        print(colored(f"- Directory Authority: Port {dir_auth_port}", 'yellow'))
        print(colored("- Relay Nodes:", 'blue'))
        for i, port in enumerate(ports[:num_relays]):
            print(colored(f"  └─ Relay {i+1}: Port {port}", 'blue'))
        print(colored("- Exit Nodes:", 'green'))
        for i, port in enumerate(ports[-num_exits:]):
            print(colored(f"  └─ Exit {i+1}: Port {port}", 'green'))

        print(colored("\nStarting client...\n", 'yellow'))
        time.sleep(2)
        
        # Start client in the main window
        run_client()

    except KeyboardInterrupt:
        print(colored("\nShutting down...", 'red'))
        sys.exit(0)
    except Exception as e:
        print(colored(f"\nError occurred: {e}", 'red'))
        sys.exit(1)

if __name__ == "__main__":
    signal.signal(signal.SIGINT, utils.socket_tool.signal_handler)
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\nShutting down...", 'red'))
        sys.exit(0)