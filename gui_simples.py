# Programa Honeypot - Programação Aplicada a Cibersegurança II
# Programa desenvolvido pelos alunos Daniel Avelino, Eric Silva e Martim Batel com auxílio de Youtube, Github e ferramentas de AI(Ex. chatgpt, gemini, deepseek).
# Este código foi comentado com "#" em vez de Docstrings(""") por motivos de conforto ocular, por favor stor não nos desconte nota por isto :).

# Bloco de Imports do programa:
import tkinter as tk
from honeypot import HoneypotSSH
import threading
import logging

# Bloco da Interface Gráfica:
# Define a Interface Gráfica para controlar o programa "Honeypot.py";
class SimpleGUI(tk.Tk):
    def __init__(self):
        
        # Criação da janela da interface gráfica e todos os seus elementos;
        super().__init__()
        self.title("Interface Gráfica - Honeypot Simples")
        self.geometry("1024x768")

        # Whitelist do Honeypot;
        self.whitelist = ["127.0.0.1", "10.0.2.15"]

         # Área de texto para exibir os logs do honeypot em tempo real.
        self.text_area = tk.Text(self, state="disabled", bg="black", fg="lime")
        self.text_area.pack(expand=True, fill="both", padx=10, pady=10)

          # Botão para iniciar o servidor honeypot.
        self.start_btn = tk.Button(self, text="Iniciar Honeypot", command=self.start_honeypot)
        self.start_btn.pack(side=tk.LEFT, padx=10, pady=10)

        # Botão para parar o servidor honeypot.
        self.stop_btn = tk.Button(self, text="Parar", command=self.stop_honeypot)
        self.stop_btn.pack(side=tk.RIGHT, padx=10, pady=10)

        self.honeypot = HoneypotSSH(gui=self)
        self.honeypot_thread = None # Variável para guardar a thread do honeypot.

    # Exibe uma mensagem na àrea de texto da Interface Gráfica;
    def log_message(self, message):
        self.text_area.config(state="normal")
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.see(tk.END)
        self.text_area.config(state="disabled")

    # Inicializa o HONEYPOT numa thread separada, assim impede o bloqueio da Interface Gráfica;
    def start_honeypot(self):

        # Garante que não são inicidas várias threads.
        if not self.honeypot_thread or not self.honeypot_thread.is_alive():
            self.honeypot_thread = threading.Thread(target=self.honeypot.start, daemon=True)
            self.honeypot_thread.start()
            self.log_message("[GUI] Honeypot iniciado.")
            logging.info("Honeypot iniciado pelo utilizador.")

    # Sinaliza ao honeypot para parar de correr;
    def stop_honeypot(self):
        self.honeypot.stop()
        self.log_message("[GUI] Honeypot parado.")
        logging.info("Honeypot parado pelo utilizador.")

if __name__ == "__main__":
    app = SimpleGUI()
    app.mainloop()
