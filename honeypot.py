# Programa Honeypot - Programação Aplicada a Cibersegurança II
# Programa desenvolvido pelos alunos Daniel Avelino, Eric Silva e Martim Batel com auxílio de Youtube, Github e ferramentas de AI(Ex. chatgpt, gemini, deepseek).
# Este código foi comentado com "#" em vez de Docstrings(""") por motivos de conforto ocular, por favor stor não nos desconte nota por isto :).

# Bloco de Imports do programa:
import socket # Biblioteca necessária para a criação do servidor e comunicação com a rede;
import paramiko # Biblioteca de implementação da comunicação SSH;
import threading # Biblioteca de gestão do servidor (Confirmar porque acho que não é bem isso);
import json # Biblioteca utilizada para guardar os logs;
import requests # Biblioteca de requestes à API;
from datetime import datetime # Biblioteca - Data e Hora dos logs guardados;


# Bloco de variáveis e configurações globais do programa:
# Chave de API para autenticação do serviço "Threat Intelligence AbuseIPDB";
ABUSE_API_KEY = "ede0725a53bb9dec61a8a3bcaf31bc38ab58389cb572c33a8793e36ac43f8e8551c305833bb50876"

# Score de confiança a partir do qual um IP é bloquado. Se "score" >= a 50 o IP é bloqueado.
BLOCK_THRESHOLD = 50

# IPs que nunca serão bloquados pelo programa;
WHITELIST = ["127.0.0.1","10.0.2.15"]


# Bloco de Funções da Firewall Dinâmica:
# Firewall dinâmica que mantêm um registo dos IPs bloquados, motivo e data;
class FirewallDinamica:

    # Função de arranque da firewall, riando assim a lista dos IPs bloquados;
    def __init__(self):
        self.ips_bloqueados = {} # Dicionário onde os IPs bloquados ficaram armazenados;

    # Função que adiciona o IP bloqueado à lista de bloqueio; (Trabalha em conjunto com o bloco "if" que se encontra de seguida);
    def bloquear_ip(self,ip,motivo):

        # "If" que garante que o IP só é adicionado à lista uma vez;
        if ip not in self.ips_bloqueados:
            self.ips_bloqueados[ip]= {
                "Motivo": motivo,
                "Data e Hora": datetime.now().isoformat()
            }
            print(f"[FIREWALL] IP  {ip} bloqueado. Motivo:{motivo}")

    # Função que verifica se o IP já se encontra na lista de IPs bloquados.
    # Resultado boleano "TRUE/FALSE" dependendo do score de reputação do IP a ser analisado;
    def verificar_bloqueio(self, ip):
        return ip in self.ips_bloqueados

# Instância criada para garantir que o objeto firewall é partilhado por todo o programa;
firewall = FirewallDinamica()


# Bloco de funções de Threat Intelligence:
# Função que verifica a API do AbuseIPDB para verificar o "score" de reputação de um IP;
def verificar_ip_abuseipdb(ip): # Design "fail-safe", caso algum erro assume que o IP é seguro e deixa passar pela firewall;
     
    try:
        # Execução do pedido GET com timeout de 5 segundos. Evita bloqueios;
        resposta = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers = {"Key": ABUSE_API_KEY, "Accept": "application/json"},
            params = {"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=5
        )

        # Executa a extração dos dados necessários da resposta JSON.
        dados = resposta.json()["data"]

        # Return que trabalha com o "BLOCK_THRESHOLD" definido no inicio do código para bloquear o IP com base no "score" de confiança ou na quantidade de reports;
        return dados["abuseConfidenceScore"] >= BLOCK_THRESHOLD or dados["totalReports"] > 5

        # Em caso de qualquer erro (ex: falha de rede, API offline), regista o problema;
    except Exception as e :
        print(f"[ERRO] API AbuseIPDB: {e}")

        # Retorna False para não bloquear o funcionamento do honeypot (fail-safe discutido anteriormente);
        return False


#Bloco de código do HONEYPOT SHH:
# Dicionário global utilizado para dar track (monitorar) a quantidade de acessos dos IPs;
tentativas_de_acesso ={}

# Através da bibliotca "PARAMIKO" é gerada uma chave RSA utilizada para a negociação do protocolo SSH;
hostkey = paramiko.RSAKey.generate(2048)

class HoneypotServer(paramiko.ServerInterface):

    # Função de inicialização do servidor para conexão específica;
    def __init__(self, ip):
        self.ip =ip # Armazena o IP conectado "atualmente" (naquele momento);

    def check_auth_password(self, username, password):

        # Aumenta o incrementador consoante a quantidade de tentativas de login do IP;
        tentativas_de_acesso[self.ip] = tentativas_de_acesso.get(self.ip, 0) +1 

        # Cria um registo de LOG detalhado da tentativa de conexão;
        log ={
            "Data e Hora": datetime.now().isoformat(),
            "ip": self.ip,
            "username": username,
            "password": password,
            "tentativas": tentativas_de_acesso[self.ip]
        }

        # Escreve o LOG em formato JSON no ficheiro.
        with open("tentativas_ssh.json", "a") as f:
            f.write(json.dumps(log) + "\n")

        print(f"[!] Tentativa e Login: {self.ip} -> {username}/{password}")

        # Verifica a quantidade de tentativas de um IP, caso seja >= 3 assume que é um ataque de Brute Force;
        if tentativas_de_acesso[self.ip] >=3:
            firewall.bloquear_ip(self.ip, motivo="Brute Force SSH")
            return 1

        return 1 # paramiko.AUTH_FAILED

    # Informa o "cliente" de que "password" é um método aceite;
    def get_allowed_auths(self, username):
        return "password"

    # Função chamada quando acontece uma tentiva de abrir um canal (Ex: Shell);
    # Finge aceitar a conexão para manter o "cliente" conectado;
    def check_channel_request(self, kind, chanid):
        return 0 if kind == "session" else 1 



# Main bloco de execução do servidor:
# Função que configura o Socket do servidor e entra em ação para gerir as conexões recebidas;
def main():

    # Configuração do Servidor;
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Associa o socket a todas as interfaces de rede na porta 2222;
    server_socket.bind(("0.0.0.0", 2222))
    server_socket.listen(100)
    print("HONEYPOT SSH ativo na porta 2222!")

    # Ciclo "WHILE" para aceitar conexões de forma contínua;
    while True:
        client_socket, client_addr = server_socket.accept()
        ip = client_addr[0]

    # Início das verificações de segurança;
        #Verifica se o IP se encontra na Whitelist definida no inicio do código;
        if ip in WHITELIST:
            print(f"[!] Conexão ignorada (whitelist): {ip}")
            client_socket.close()
            continue

        # Verifica se o IP já foi bloqueado pela Firewall;
        if firewall.verificar_bloqueio(ip):
            print(f"[! Conexão bloqueada (firewall: {ip})]")
            client_socket.close()
            continue

        # Consulta a reputação de IP nas fontes Threat IntelligenceM
        if verificar_ip_abuseipdb(ip):
            firewall.bloquear_ip(ip, motivo="AbuseIPDB")
            client_socket.close()
            continue 
    # Fim das verificações de segurança;

    # Caso o IP passe por todos os filtros entrega a conexão ao Paramiko;
        try:
            # Cria o trosnporte SSH do cliente sobre do socket;
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(hostkey)

            # Inicia o servidor SSH com a lógica definida anteriormente;
            servidor = HoneypotServer(ip)
            transport.start_server(server= servidor)
            canal = transport.accept(20)
            if canal:
                canal.close()

        except Exception as e :
            print(f"[ERRO] {e}")
        finally:
            # Garante que o socket do cliente é fechado no final;
            client_socket.close()


# Caso o ficheiro seja corrido diretamente, dá "handle" da sua execução;
if __name__ == "__main__":
    main()


class HoneypotSSH:
    # Inicialização do Controlador do HONEYPOT;
    def __init__(self, gui=None):
        self.running = False
        self.gui = gui

    # Inicialização do Servidor;
    def start(self):
        self.running = True
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(("0.0.0.0", 2222))
        server_socket.listen(100)

        # Envia mensagem de início para a Interface Gráfica;
        if self.gui:
            self.gui.log_message("HONEYPOT SSH ativo na porta 2222!")
        else:
            print("HONEYPOT SSH ativo na porta 2222!")

         # O ciclo principal só executa enquanto a flag 'running' for True;
        while self.running:
            try:
                client_socket, client_addr = server_socket.accept()
                ip = client_addr[0]


            # A cadeia de filtros é idêntica à função main mas desta vez com LOGGING para a Interface Gráfica;
                if ip in WHITELIST:
                    if self.gui:
                        self.gui.log_message(f"[!] Conexão ignorada (whitelist): {ip}")
                    client_socket.close()
                    continue

                if firewall.verificar_bloqueio(ip):
                    if self.gui:
                        self.gui.log_message(f"[!] Conexão bloqueada (firewall): {ip}")
                    client_socket.close()
                    continue

                if verificar_ip_abuseipdb(ip):
                    firewall.bloquear_ip(ip, motivo="AbuseIPDB")
                    client_socket.close()
                    continue

                # Bloco de código que entrega a conexão ao Paramiko.
                transport = paramiko.Transport(client_socket)
                transport.add_server_key(hostkey)
                servidor = HoneypotServer(ip)
                transport.start_server(server=servidor)
                canal = transport.accept(20)
                if canal:
                    canal.close()

            except Exception as e:
                # LOG de erros também é enviado para a Interface Gráfica;
                if self.gui:
                    self.gui.log_message(f"[ERRO] {e}")
                else:
                    print(f"[ERRO] {e}")

            finally:
                # Garante que o socket do cliente é fechado no fim do programa;
                client_socket.close()

        # No fim do ciclo fecha o socket;
        server_socket.close()

    def stop(self):
        print("A iniciar o processo de paragem do Honeypot!")
        self.running = False

        # Bloco para garantir que o socket é fechado, mesmo que dê erro.
        # Isto cria uma conexão 'falsa' para desbloquear o .accept() e permitir que o ciclo principal termine de forma limpa.
        try:
            # O 'with' garante que o socket de desbloqueio é sempre fechado.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1) # Define um timeout de 1 segundo
                s.connect(("127.0.0.1", 2222))
            print("[INFO] Socket principal desbloqueado.")
        except Exception as e:
            # É normal que isto possa dar um erro se o servidor fechar muito rápido.
            # Podemos ignorar o erro com segurança.
            print(f"[INFO] Ocorreu um erro esperado ao desbloquear o socket: {e}")

        if self.gui:
            self.gui.log_message("[GUI] Servidor Honeypot parado com sucesso.")
        else:
            print("[GUI] Servidor Honeypot parado com sucesso.")
