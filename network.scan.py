import socket
import subprocess
from colorama import Fore, Style, init
import threading
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm  # Importar tqdm para la barra de progreso

# Inicializar colorama para manejar colores en la terminal
init()

def ping_host(host):
    try:
        output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
        print(f"{Fore.GREEN}[+] Host {host} está activo.{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[-] Host {host} no está activo.{Style.RESET_ALL}")

def scan_port(host, port, protocol='TCP'):
    try:
        if protocol == 'TCP':
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif protocol == 'UDP':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            print(f"{Fore.YELLOW}[!] Protocolo no reconocido.{Style.RESET_ALL}")
            return

        sock.settimeout(0.2)  # Reducir aún más el timeout para acelerar el escaneo
        result = sock.connect_ex((host, port))
        if result == 0:
            print(f"{Fore.GREEN}[+] Puerto {port}/{protocol} está abierto en {host}.{Style.RESET_ALL}")
        sock.close()
    except socket.error:
        print(f"{Fore.RED}[-] Error al intentar escanear el puerto {port}.{Style.RESET_ALL}")

def scan_ports(host, protocol='TCP', max_threads=400):
    ports = range(1, 65536)  # Escanear todos los puertos (1 a 65535)
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        list(tqdm(executor.map(lambda p: scan_port(host, p, protocol), ports), total=len(ports), desc="Escaneando puertos", ncols=100))

def icmp_scan(host):
    try:
        output = subprocess.check_output(f"hping3 -1 {host}", shell=True)
        print(f"{Fore.GREEN}[+] ICMP scan exitoso para {host}.{Style.RESET_ALL}")
    except subprocess.CalledProcessError:
        print(f"{Fore.RED}[-] ICMP scan fallido para {host}.{Style.RESET_ALL}")
    except FileNotFoundError:
        print(f"{Fore.RED}[-] hping3 no está instalado. Instálalo para realizar escaneos ICMP.{Style.RESET_ALL}")

def threaded_scan(host, scan_type):
    if scan_type == 'ping':
        ping_host(host)
    elif scan_type == 'tcp':
        scan_ports(host, protocol='TCP')
    elif scan_type == 'udp':
        scan_ports(host, protocol='UDP')
    elif scan_type == 'icmp':
        icmp_scan(host)
    else:
        print(f"{Fore.YELLOW}[!] Tipo de escaneo no reconocido.{Style.RESET_ALL}")

def main():
    print(f"{Fore.CYAN}--- Herramienta Avanzada de Escaneo de Red ---{Style.RESET_ALL}")
    host = input(f"{Fore.YELLOW}Ingrese la dirección IP o el nombre del host: {Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}--- Opciones de Escaneo ---{Style.RESET_ALL}")
    print("1. Ping")
    print("2. Escaneo de Puertos TCP")
    print("3. Escaneo de Puertos UDP")
    print("4. Escaneo ICMP")

    option = input(f"{Fore.YELLOW}Seleccione una opción: {Style.RESET_ALL}")

    if option == '1':
        scan_type = 'ping'
    elif option == '2':
        scan_type = 'tcp'
    elif option == '3':
        scan_type = 'udp'
    elif option == '4':
        scan_type = 'icmp'
    else:
        print(f"{Fore.RED}Opción inválida.{Style.RESET_ALL}")
        return

    # Crear un hilo para ejecutar el escaneo seleccionado
    scan_thread = threading.Thread(target=threaded_scan, args=(host, scan_type))
    scan_thread.start()
    scan_thread.join()

    # Mensaje de agradecimiento al finalizar
    print(f"{Fore.MAGENTA}Gracias por utilizar la herramienta Sael-scan{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

