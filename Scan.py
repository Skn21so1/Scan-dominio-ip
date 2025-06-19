import socket
import threading
import requests
import dns.resolver 

from requests.exceptions import RequestException
from urllib.parse import urljoin


portas = [21, 22, 23, 25, 53, 80, 110, 443, 3306, 8080, 8443]
caminhos_paineis = ['/admin', '/login', '/wp-login.php', '/cpanel', '/administrator']
subdominios_comuns = ['www','mail','ftp','api','dev','test',]
tempo_timeout = 0.5
lock = threading.Lock()
usar_tor = True

proxy_tor = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

def resolver_subdominios(dominio):
    encontrados = []
    for sub in subdominios_comuns:
        host = f"{sub}.{dominio}"
        try:
            dns.resolver.resolve(host, 'A', lifetime=2)
            encontrados.append(host)
        except:
            pass
    return encontrados

def scan_port(ip, porta):
    try:
        cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cliente.settimeout(tempo_timeout)
        if cliente.connect_ex((ip, porta)) == 0:
            with lock:
                print(f" Porta {porta} ABERTA no IP {ip}")
                if porta in [80, 443, 8080, 8443]:
                    bruteforce_paineis_web(ip, porta)
        cliente.close()
    except:
        pass

def bruteforce_paineis_web(ip, porta):
    protocolos = ['https'] if porta in [443, 8443] else ['http']
    for protocolo in protocolos:
        base = f"{protocolo}://{ip}:{porta}"
        for caminho in caminhos_paineis:
            url = urljoin(base, caminho)
            try:
                r = requests.get(url, proxies=proxy_tor if usar_tor else None, timeout=3, verify=False)
                if r.status_code in [200, 401, 403]:
                    print(f" Painel detectado: {url} [{r.status_code}]")
            except RequestException:
                pass

def detect_firewall(dominio):
    for protocolo in ['http', 'https']:
        url = f"{protocolo}://{dominio}"
        try:
            r = requests.get(url, proxies=proxy_tor if usar_tor else None, timeout=5, verify=False)
            headers = {k.lower(): v for k, v in r.headers.items()}
            servidor = headers.get('server', '')
            via = headers.get('via', '')
            cf = headers.get('cf-ray', '')
            waf = headers.get('x-sucuri-cache', '') or headers.get('x-incap-client-ip', '')

            if 'cloudflare' in servidor.lower() or cf:
                print(f" Firewall detectado (Cloudflare) via {protocolo.upper()}")
            elif 'sucuri' in servidor.lower() or waf:
                print(f" Firewall detectado (Sucuri) via {protocolo.upper()}")
            elif 'imperva' in servidor.lower() or 'incapsula' in servidor.lower():
                print(f" Firewall detectado (Imperva/Incapsula) via {protocolo.upper()}")
            elif via:
                print(f" Proxy detectado (header Via) via {protocolo.upper()}")
            else:
                print(f" Sem firewall conhecido via {protocolo.upper()}")
            return
        except Exception as e:
            print(f" Erro detectando firewall via {protocolo.upper()}: {e}")

def resolver_todos_ips(host):
    ips = set()
    for tipo in ['A','AAAA']:
        try:
            for r in dns.resolver.resolve(host, tipo, lifetime=2):
                ips.add(r.address)
        except:
            pass
    return list(ips)

def scan_target(host, mostrar_firewall=False):
    if mostrar_firewall:
        print(f"\n Detectando firewall para {host}...")
        detect_firewall(host)

    ips = resolver_todos_ips(host)
    if not ips:
        print(f" Nenhum IP descoberto para {host}")
        return

    print(f"\n IPs de {host}: {', '.join(ips)}")

    for ip in ips:
        print(f"\n Escaneando IP {ip}...")
        threads = [threading.Thread(target=scan_port, args=(ip, p)) for p in portas]
        for t in threads: t.start()
        for t in threads: t.join()
    print("\n Scan concluído.")

def main():
    print("""
 

[1] ✅ Escanear IP
[2] ✅ Escanear domínio
    """)
    op = input("Opção: ")

    if op == '1':
        alvo = input("Digite IP ou domínio: ")
        scan_target(alvo, mostrar_firewall=True)

    elif op == '2':
        dom = input("Digite o domínio: ")
        hosts = [dom] + resolver_subdominios(dom)
        if hosts:
            print(f"\n Subdomínios encontrados: {hosts}")
            for h in hosts:
                scan_target(h, mostrar_firewall=True)
        else:
            print(" Nenhum subdomínio detectado.")
    else:
        print(" Opção Inválida.")

if __name__ == "__main__":
    main()
