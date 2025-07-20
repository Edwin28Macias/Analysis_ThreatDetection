from scapy.all import rdpcap, Raw, TCP, DNS
from scapy.layers.http import HTTP

def analyze_pcap(pcap_path):
    """
    Analisa um arquivo .pcap para detectar possíveis credenciais HTTP em texto plano
    e anomalias básicas em consultas DNS.
    """
    print(f"\n[*] Starting PCAP file analysis: {pcap_path}")
    
    try:
        packets = rdpcap(pcap_path) # Lê todos os pacotes do arquivo .pcap
    except FileNotFoundError:
        print(f"[ERROR] The file '{pcap_path}' was not found. Make sure it's in the same directory as the script or that the path is correct.")
        return
    except Exception as e:
        print(f"[ERROR] An error occurred while reading the PCAP file: {e}")
        return

    print(f"[*] Loaded {len(packets)} packets.")

    found_credentials = []
    
    # --- HTTP Credential Detection ---
    print("\n--- Searching for Cleartext HTTP Credentials ---")
    for i, packet in enumerate(packets):
        # Procuramos por pacotes que contenham a camada HTTP e dados brutos (Raw)
        if packet.haslayer(HTTP) and packet.haslayer(Raw):
            # Verificamos se é uma requisição POST (comum para o envio de formulários de login)
            # Ou se é uma requisição GET com parâmetros na URL que poderiam ser credenciais
            http_layer = packet[HTTP]
            http_payload = packet[Raw].load

            # Verifica se é uma requisição HTTP POST
            is_post = b"POST" in bytes(http_layer)
            
            # Tenta decodificar os dados brutos como texto
            try:
                http_data = http_payload.decode('utf-8', errors='ignore')
                
                # Procura por padrões comuns de campos de credenciais no corpo da requisição
                # (apenas se for um POST; GETs levariam os dados na URL, que já faz parte da camada HTTP)
                if is_post:
                    keywords_to_check = ["user=", "pass=", "username=", "password=", "pwd="]
                    if any(keyword in http_data.lower() for keyword in keywords_to_check):
                        # Filtra algumas URLs ou conteúdos comuns que poderiam ser falsos positivos (ex: Google Analytics, pixels de rastreamento)
                        if not any(fpp_keyword in http_data.lower() for fpp_keyword in ["google-analytics", "gtm.js", ".gif", ".png", ".jpg", "favicon.ico"]):
                            print(f"\n[!!!] Possible Cleartext HTTP Credentials detected in Packet #{i+1} (Time: {packet.time}):")
                            print(f"    URL: {http_layer.Host.decode('utf-8', errors='ignore')}{http_layer.Path.decode('utf-8', errors='ignore')}")
                            if packet.haslayer(TCP):
                                print(f"    Source IP: {packet.src}:{packet[TCP].sport} -> Dest IP: {packet.dst}:{packet[TCP].dport}")
                            print("    POST Data (possible credentials):")
                            print(http_data)
                            found_credentials.append((packet.time, http_layer.Host, http_layer.Path, http_data))
                
                # Para requisições GET, procura por parâmetros na URL (Path)
                elif b"GET" in bytes(http_layer):
                     # Converte Path para string e coloca em minúsculas para procurar padrões
                    path_str = http_layer.Path.decode('utf-8', errors='ignore').lower()
                    keywords_in_url = ["user=", "pass=", "username=", "password=", "pwd="]
                    if any(keyword in path_str for keyword in keywords_in_url):
                         print(f"\n[!!!] Possible Cleartext HTTP Credentials in URL (GET) detected in Packet #{i+1} (Time: {packet.time}):")
                         print(f"    Full URL: {http_layer.Host.decode('utf-8', errors='ignore')}{http_layer.Path.decode('utf-8', errors='ignore')}")
                         if packet.haslayer(TCP):
                             print(f"    Source IP: {packet.src}:{packet[TCP].sport} -> Dest IP: {packet.dst}:{packet[TCP].dport}")
                         found_credentials.append((packet.time, http_layer.Host, http_layer.Path, "GET parameters in URL"))


            except UnicodeDecodeError:
                # Não foi possível decodificar como UTF-8, simplesmente ignora esses casos para não parar o script
                pass
    
    if not found_credentials:
        print("[*] No obvious cleartext HTTP credentials detected in the analyzed packets.")
    else:
        print(f"\n[+] {len(found_credentials)} possible instance(s) of cleartext HTTP credentials found.")


# --- DNS Anomaly Analysis ---
    print("\n--- Starting DNS Anomaly Analysis ---")
    long_dns_queries = []

    # Define um limite para nomes DNS "longos" (ex: mais de 25 caracteres, excluindo pontos)
    # Este é um valor arbitrário para demonstração; a detecção no mundo real pode usar análise estatística
    DNS_NAME_LENGTH_THRESHOLD = 25 

    for i, packet in enumerate(packets):
        # Verifica se o pacote tem uma camada DNS e é uma consulta (opcode=0)
        if packet.haslayer(DNS) and packet[DNS].qr == 0: # qr == 0 significa que é uma consulta
            dns_layer = packet[DNS]

            # Verifica se há um Registro de Questão DNS (DNSRR - DNS Resource Record para respostas, DNSQR para consultas)
            if hasattr(dns_layer, 'qd') and dns_layer.qd:
                query_name = dns_layer.qd.qname.decode('utf-8', errors='ignore')

                # Remove o ponto final se presente e conta o comprimento
                if query_name.endswith('.'):
                    query_name = query_name[:-1]

                # Remove o sufixo de domínio (ex: .com, .org) para um comprimento mais preciso
                # Esta é uma simplificação; uma solução robusta usaria uma Lista de Sufixos Públicos
                parts = query_name.split('.')
                effective_name_length = 0
                if len(parts) > 1: # Se há pelo menos um ponto, assume que há um TLD ou subdomínio
                    # Considera o comprimento da primeira parte do nome de domínio (subdomínio.dominio.tld -> 'subdominio')
                    effective_name_length = len(parts[0]) 
                else:
                    # Se não há pontos, considera o nome completo
                    effective_name_length = len(query_name) 

                if effective_name_length > DNS_NAME_LENGTH_THRESHOLD:
                    print(f"\n[!!!] Possible DNS Anomaly (Long Query Name) detected in Packet #{i+1} (Time: {packet.time}):")
                    print(f"    Query Name: {query_name} (Length: {effective_name_length})")
                    if packet.haslayer(TCP): # DNS também pode rodar sobre TCP, mas geralmente UDP
                        print(f"    Source IP: {packet.src}:{packet[TCP].sport} -> Dest IP: {packet.dst}:{packet[TCP].dport}")
                    elif packet.haslayer(UDP): # Mais comum para DNS
                         print(f"    Source IP: {packet.src}:{packet[UDP].sport} -> Dest IP: {packet.dst}:{packet[UDP].dport}")
                    long_dns_queries.append((packet.time, query_name))

    if not long_dns_queries:
        print("[*] No obvious long DNS queries (anomalies) detected.")
    else:
        print(f"\n[+] {len(long_dns_queries)} possible DNS anomaly (long query name) instance(s) found.")


# --- Ponto de entrada do script ---
if __name__ == "__main__":
    # O arquivo "my_capture.pcap" foi o arquivo usado para fazer esta atividade
    # Para analisar seu próprio arquivo .pcap, modifique o caminho abaixo.
    pcap_file_path = "my_capture.pcap" 
    analyze_pcap(pcap_file_path)
