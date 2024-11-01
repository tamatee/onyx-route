import threading
import time
import signal
import utils
import random
from termcolor import colored
from utils import client, directory_authority, node, socket_tool
import sys
import utils.socket_tool

def run_directory_authority():
    directory_authority.main()

def run_node(port, is_exit=False):
    node.main(port=port, is_exit=is_exit)

def run_client():
    client.main()

def main():
    # Configuration
    num_relays = 3
    num_exits = 1
    dir_auth_port = 12345
    # Start Directory Authority in a thread
    da_thread = threading.Thread(target=run_directory_authority)
    da_thread.daemon = True
    da_thread.start()
    print(colored("Started Directory Authority...", 'green'))
    time.sleep(1)  # รอให้ DA พร้อม
    # Start Relay Nodes
    port_range = list(range(7000, 7010))
    ports = random.sample(port_range, num_relays + num_exits)
    relay_threads = []
    # Start relay nodes
    for port in ports[:num_relays]:
        thread = threading.Thread(target=run_node, args=(port,))
        thread.daemon = True
        thread.start()
        relay_threads.append(thread)
        print(colored(f"Started Relay Node on port {port}...", 'green'))
        time.sleep(1)   
    # Start exit nodes
    for port in ports[-1 * num_exits:]:
        thread = threading.Thread(target=run_node, args=(port, True))
        thread.daemon = True
        thread.start()
        relay_threads.append(thread)
        print(colored(f"Started Exit Node on port {port}...", 'green'))
        time.sleep(1)   
    print(colored("\nAll nodes are running. Starting client...\n", 'yellow'))   
    try:
        # Start client
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