import customtkinter as ctk  # type: ignore
import threading
import time
import requests
import psutil
import os
import hashlib
import json
import mss
import pytesseract
import pyperclip
from PIL import Image, ImageTk
import pystray
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from dotenv import load_dotenv
import shutil
import unicodedata
from urllib.parse import urlparse
import numpy as np
import sys

try:
    IsolationForest = __import__("sklearn.ensemble", fromlist=["IsolationForest"]).IsolationForest
except ImportError:
    class IsolationForest:
        """Lightweight fallback when scikit-learn is unavailable."""
        def __init__(self, contamination=0.1, random_state=None):
            self.contamination = contamination
            self.center = None
            self.scale = None

        def fit(self, dados):
            dados = np.asarray(dados, dtype=float)
            self.center = np.median(dados, axis=0)
            self.scale = np.median(np.abs(dados - self.center), axis=0)
            self.scale[self.scale == 0] = 1.0
            return self

        def predict(self, dados):
            dados = np.asarray(dados, dtype=float)
            distancia = np.max(np.abs(dados - self.center) / self.scale, axis=1)
            return np.where(distancia > 3.0, -1, 1)

# --- CONFIGURAÇÕES E DIRETÓRIO DO PROJETO ---
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
PASTA_DOWNLOADS = os.path.expanduser("~/Downloads")

DIRETORIO_PROJETO = os.path.dirname(os.path.abspath(__file__))
CAMINHO_ICONE_PADRAO = os.path.join(DIRETORIO_PROJETO, "icone5.png")
PASTA_QUARENTENA = os.path.join(DIRETORIO_PROJETO, "quarentena")
ARQUIVO_WHITELIST = os.path.join(DIRETORIO_PROJETO, "whitelist.json")
ARQUIVO_LOG_FORENSE = os.path.join(DIRETORIO_PROJETO, "forense.json")

os.makedirs(PASTA_QUARENTENA, exist_ok=True)

if os.name == 'nt':
    PASTAS_SISTEMA_CRITICAS = [r"C:\Windows\System32"]
else:
    PASTAS_SISTEMA_CRITICAS = ["/etc"]

ARQUIVO_LOCK = os.path.expanduser("~/.copiloto_cybersec.lock")

def verificar_instancia_unica():
    if os.path.exists(ARQUIVO_LOCK):
        try:
            with open(ARQUIVO_LOCK, "r") as f:
                pid_antigo = int(f.read().strip())
            if psutil.pid_exists(pid_antigo):
                print("⚠️ O Copiloto CyberSec já está rodando em segundo plano!")
                sys.exit(0)
        except:
            pass
    with open(ARQUIVO_LOCK, "w") as f:
        f.write(str(os.getpid()))

def registrar_log_forense(tipo_evento, detalhes):
    try:
        evento = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "tipo": tipo_evento,
            "detalhes": detalhes
        }
        logs = []
        if os.path.exists(ARQUIVO_LOG_FORENSE):
            with open(ARQUIVO_LOG_FORENSE, "r", encoding="utf-8") as f:
                try:
                    logs = json.load(f)
                    if not isinstance(logs, list):
                        logs = []
                except:
                    logs = []
        logs.append(evento)
        
        if len(logs) > 1000:
            logs = logs[-1000:]
            
        with open(ARQUIVO_LOG_FORENSE, "w", encoding="utf-8") as f:
            json.dump(logs, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"Erro ao salvar log forense: {e}")

def avaliar_heuristica_url(texto_url):
    try:
        parsed = urlparse(texto_url)
        dominio = parsed.netloc.lower() if parsed.netloc else parsed.path.split('/')[0].lower()
        path = parsed.path.lower()
        
        tlds_perigosos = ['.zip', '.mov', '.click', '.top', '.gq', '.ml', '.cf', '.tk', '.cc', '.su']
        if any(dominio.endswith(tld) for tld in tlds_perigosos):
            return True, f"Domínio utiliza TLD de altíssimo risco ou abusado ({dominio})"
            
        import re
        ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
        host_limpo = dominio.split(':')[0]
        if ip_pattern.match(host_limpo) and not host_limpo.startswith("127.") and not host_limpo.startswith("192.168."):
            return True, f"Uso de endereço IP bruto na URL ({host_limpo}), comportamento típico de phishing/C2"
            
        palavras_phishing = ['login', 'signin', 'auth', 'verificacao', 'seguranca', 'atualizar', 'banco', 'suporte', 'wallet', 'acesso']
        if any(p in dominio or p in path for p in palavras_phishing):
            return False, f"Contém termos sensíveis, requer atenção da IA."
            
        return False, "Nenhum gatilho heurístico crítico imediato."
    except Exception as e:
        return False, f"Erro na heurística: {e}"

def consultar_llama_local(prompt, max_tokens=300, temperature=0.1, retries=2):
    url = "http://127.0.0.1:8000/v1/completions"
    payload = {
        "prompt": prompt,
        "max_tokens": max_tokens,
        "temperature": temperature
    }
    for tentativa in range(retries + 1):
        try:
            r = requests.post(url, json=payload, timeout=30)
            if r.status_code == 200:
                dados = r.json()
                if 'choices' in dados and len(dados['choices']) > 0:
                    return dados['choices'][0]['text'].strip()
                elif 'content' in dados:
                    return dados['content'].strip()
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            if tentativa == retries:
                return "⚠️ Erro: Servidor Llama local indisponível ou demorou a responder."
            time.sleep(2)
        except Exception as e:
            return f"⚠️ Erro na resposta da IA: {e}"
    return "⚠️ Falha de comunicação com a IA."

def carregar_whitelist():
    try:
        with open(ARQUIVO_WHITELIST, "r", encoding="utf-8") as f:
            dados = json.load(f)
        return dados if isinstance(dados, list) else []
    except (OSError, json.JSONDecodeError):
        return []

def salvar_whitelist(lista):
    with open(ARQUIVO_WHITELIST, "w") as f:
        json.dump(lista, f)

WHITELIST = carregar_whitelist()

def is_whitelisted(nome_processo, cmdline=""):
    if not nome_processo:
        return False
    nome_lower = nome_processo.lower()
    cmd_lower = cmdline.lower() if cmdline else ""
    
    for w in WHITELIST:
        w_clean = w.lower().strip()
        if not w_clean:
            continue
        if w_clean == nome_lower or nome_lower.startswith(w_clean) or w_clean in cmd_lower:
            return True
    return False

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

FONTE_TEXTO = ("Arial", 22)
FONTE_TITULO = ("Arial", 28, "bold")
FONTE_BOTAO = ("Arial", 22, "bold")

app_ui = None
ml_model = None
arquivos_processados = set()

def treinar_baseline_inicial():
    global ml_model
    dados_normais = np.array([[0.5, 1.2, 4], [2.0, 3.5, 12], [0.1, 0.5, 2], [15.0, 8.0, 20], [0.0, 0.2, 1]])
    ml_model = IsolationForest(contamination=0.20, random_state=42)
    ml_model.fit(dados_normais)

def quarentena_arquivo(caminho_origem, nome_arquivo):
    try:
        destino = os.path.join(PASTA_QUARENTENA, nome_arquivo)
        shutil.move(caminho_origem, destino)
        os.chmod(destino, 0o000)
        registrar_log_forense("QUARENTENA_ATIVADA", {"arquivo": nome_arquivo, "caminho_original": caminho_origem})
        return True
    except Exception as e:
        print(f"Erro ao colocar em quarentena: {e}")
        return False

def checar_virustotal(hash_arquivo, nome_arquivo, caminho_completo):
    if not VIRUSTOTAL_API_KEY:
        if app_ui:
            app_ui.after(0, lambda: app_ui.add_log_download(nome_arquivo, "⚠️ ERRO: Chave VirusTotal não encontrada."))
        return
    url = f"https://virustotal.com{hash_arquivo}"
    try:
        r = requests.get(url, headers={"x-apikey": VIRUSTOTAL_API_KEY})
        if r.status_code == 200:
            stats = r.json()['data']['attributes']['last_analysis_stats']
            maliciosos = stats['malicious']
            if app_ui:
                if maliciosos > 0:
                    app_ui.after(0, lambda: app_ui.add_log_download(nome_arquivo, "🚨 DETECTADO! Movido para Quarentena."))
                    quarentena_arquivo(caminho_completo, nome_arquivo)
                    app_ui.after(0, lambda: app_ui.mostrar_alerta_bloqueio("🚨 AMEAÇA EM QUARENTENA!", f"O arquivo '{nome_arquivo}' foi isolado com segurança!"))
                else:
                    app_ui.after(0, lambda: app_ui.add_log_download(nome_arquivo, "✅ Arquivo limpo."))
                    app_ui.after(0, lambda: app_ui.mostrar_toast("✅ Download Seguro", f"'{nome_arquivo}' está limpo.", "#00ff00"))
    except Exception as e:
        if app_ui:
            app_ui.after(0, lambda: app_ui.add_log_download(nome_arquivo, f"❌ Erro na API VT: {e}"))

class MonitorArquivos(FileSystemEventHandler):
    def __init__(self, tipo="download"):
        self.tipo = tipo
        self.ultimo_alerta = 0
    def on_created(self, event): self._proc(event.src_path)
    def on_modified(self, event):
        if self.tipo == "sistema": self._proc(event.src_path)
    def on_moved(self, event): self._proc(event.dest_path)
    def _proc(self, caminho):
        if not os.path.isdir(caminho):
            nome = os.path.basename(caminho)
            if self.tipo == "sistema":
                if nome.endswith('~') or '.swp' in nome or '.lock' in nome: return
                tempo_atual = time.time()
                if (tempo_atual - self.ultimo_alerta) < 2.0: return
                self.ultimo_alerta = tempo_atual
                
                if app_ui:
                    registrar_log_forense("MODIFICACAO_SISTEMA_CRITICO", {"caminho": caminho})
                    
                    prompt = f"""<|user|>
[CONTEXTO DE SISTEMA]
Você é um Analista de Segurança Forense Sênior em Linux Mint. Um arquivo em uma pasta crítica do sistema foi modificado.
- Caminho alterado: {caminho}

[DIRETRIZ DE AVALIAÇÃO]
Avalie se esta modificação em arquivo de configuração/sistema é típica de rotinas legítimas do sistema operacional (como cups, atualizações, cache) ou se indica adulteração maliciosa.

[FORMATO DE RESPOSTA]
Inicie com o veredito em negrito (**Seguro** ou **Perigo Detectado**), seguido de uma análise técnica breve de no máximo duas frases.<|end|>
<|assistant|>"""
                    
                    def analisar_sistema_async():
                        resposta_ia = consultar_llama_local(prompt, max_tokens=200, temperature=0.1)
                        app_ui.add_log_processo(f"Modificação: {nome}", resposta_ia)
                        
                        if "perigo detectado" in resposta_ia.lower() and "não" not in resposta_ia.lower():
                            app_ui.after(0, lambda: app_ui.mostrar_alerta_bloqueio("🚨 ALTERAÇÃO CRÍTICA SUSPEITA!", f"Arquivo: {caminho}\n\n{resposta_ia}"))

                    threading.Thread(target=analisar_sistema_async, daemon=True).start()
                return

            if nome.endswith('.crdownload') or nome.endswith('.part') or nome in arquivos_processados: return
            arquivos_processados.add(nome)
            time.sleep(1.5)
            try:
                sha256 = hashlib.sha256()
                with open(caminho, "rb") as f:
                    for b in iter(lambda: f.read(4096), b""): sha256.update(b)
                checar_virustotal(sha256.hexdigest(), nome, caminho)
            except: pass

def analisar_comportamento_processo(nome_processo, cpu_uso, mem_uso, cmdline, path_binario, pai_nome):
    global ml_model
    if not ml_model:
        treinar_baseline_inicial()
    if "python" in nome_processo.lower() or "agente" in nome_processo.lower():
        return

    features = np.array([[cpu_uso, mem_uso, 5]])
    previsao = ml_model.predict(features) 
    if (previsao[0] == -1 and (cpu_uso > 8.0 or mem_uso > 15.0)) or (cpu_uso > 15.0 or mem_uso > 25.0):
        prompt = f"""<|user|>
[CONTEXTO DE SISTEMA]
Você é um Analista de Segurança Forense Sênior em Linux Mint. Sua missão é separar ameaças cibernéticas reais de aplicativos legítimos de usuário. 

[TELEMETRIA DO ALERTA]
- Processo: {nome_processo}
- Linha de Comando: {cmdline}
- Binário: {path_binario}
- Processo Pai: {pai_nome}
- Consumo: CPU {cpu_uso}%, RAM {mem_uso}%

[FORMATO DE RESPOSTA]
Inicie com o veredito em negrito (**Perigo Detectado** ou **Seguro**), seguido de uma análise técnica de no máximo duas frases.<|end|>
<|assistant|>"""
        try:
            r = requests.post("http://127.0.0.1:8000/v1/completions", json={"prompt": prompt, "max_tokens": 300, "temperature": 0.1})
            texto = r.json()['choices'][0]['text'].strip()
            if app_ui:
                app_ui.add_log_processo(nome_processo, texto)
                
                texto_lower = texto.lower()
                termos_reais_perigo = ["backdoor", "trojan", "malware", "ransomware", "exploit", "payload malicioso", "rootkit"]
                tem_perigo_real = any(termo in texto_lower for termo in termos_reais_perigo)
                e_seguro = "seguro" in texto_lower or "legítimo" in texto_lower or "não é" in texto_lower
                
                if tem_perigo_real and not e_seguro:
                    registrar_log_forense("PROCESSO_ANOMALO_MALICIOSO", {"processo": nome_processo, "cpu": cpu_uso, "ia": texto})
                    app_ui.after(0, lambda: app_ui.mostrar_alerta_bloqueio("🚨 AMEAÇA REAL DETECTADA!", f"Processo: {nome_processo}\nComando: {cmdline}\n\nAnálise:\n{texto}"))
        except:
            pass

def loop_clipboard():
    ultimo_texto = ""
    while True:
        try:
            texto_atual = pyperclip.paste().strip()
            if texto_atual != ultimo_texto and (texto_atual.startswith("http://") or texto_atual.startswith("https://")):
                ultimo_texto = texto_atual
                if app_ui:
                    app_ui.after(0, lambda t=texto_atual: app_ui.add_chat_msg("Você copiou um link:", t))
                    app_ui.after(0, lambda t=texto_atual: threading.Thread(target=app_ui._analisar_url_thread, args=(t,), daemon=True).start())
        except Exception:
            pass
        time.sleep(1)

def loop_monitor_rede():
    portas_vistas = set()
    time.sleep(5)
    print("🚀 [DIAGNÓSTICO] Monitor de Rede Inicializado!", flush=True)
    
    while True:
        try:
            conexoes = psutil.net_connections(kind='inet')
            for conn in conexoes:
                pid = conn.pid
                if not pid or pid == os.getpid():
                    continue
                try:
                    proc = psutil.Process(pid)
                    nome_proc = proc.name()
                    try:
                        cmdline = " ".join(proc.cmdline())
                    except:
                        cmdline = ""

                    if is_whitelisted(nome_proc, cmdline):
                        continue
                    
                    ignorar = ["firefox", "agy", "brave", "chromium", "chrome", "systemd", "dbus", "code", "python", "nc", "netcat"]
                    if any(ign in nome_proc.lower() for ign in ignorar):
                        continue
                            
                    if conn.status == 'LISTEN' and conn.laddr:
                        porta = conn.laddr.port
                        if porta in {22, 53, 631, 5353, 8000}:
                            continue
                        
                        chave_porta = f"LISTEN-{porta}"
                        if chave_porta not in portas_vistas:
                            portas_vistas.add(chave_porta)
                                
                            prompt = f"""<|user|>
[CONTEXTO DE ANÁLISE]
Você é um Threat Hunter forense. Avalie se esta abertura de porta LISTEN representa uma ameaça ou um serviço legítimo.
- Processo: {nome_proc}
- Comando: {cmdline}
- Porta: {porta}

[FORMATO DE RESPOSTA]
Inicie com o veredito em negrito (**Perigo Detectado** ou **Seguro**), seguido de justificativa técnica com até 300 caracteres.<|end|>
<|assistant|>"""
                            r = requests.post("http://127.0.0.1:8000/v1/completions", json={"prompt": prompt, "max_tokens": 300, "temperature": 0.1})
                            texto = r.json()['choices'][0]['text'].strip()

                            if app_ui:
                                app_ui.add_log_processo(f"Porta {porta} (LISTEN)", texto)
                                
                                texto_lower = texto.lower()
                                termos_reais_perigo = ["backdoor", "trojan", "malware", "ransomware", "exploit", "payload malicioso", "rootkit"]
                                tem_perigo_real = any(termo in texto_lower for termo in termos_reais_perigo)
                                e_seguro = "seguro" in texto_lower or "legítimo" in texto_lower or "não é" in texto_lower
                                
                                if tem_perigo_real and not e_seguro:
                                    registrar_log_forense("PORTA_LISTEN_SUSPEITA", {"processo": nome_proc, "porta": porta, "ia": texto})
                                    app_ui.after(0, lambda np=nome_proc, p=porta, t=texto: app_ui.mostrar_alerta_bloqueio("🚨 PORTA DE ESCUTA COMPROMETIDA!", f"Processo: {np}\nPorta: {p}\n\nAnálise:\n{t}"))

                    elif conn.status == 'ESTABLISHED' and conn.raddr:
                        ip_remoto = conn.raddr.ip
                        porta_remota = conn.raddr.port
                        if not ip_remoto.startswith("127.") and not ip_remoto.startswith("192.168.") and not ip_remoto.startswith("10."):
                            chave_conexao = f"ESTABLISHED-{pid}-{ip_remoto}"
                            if chave_conexao not in portas_vistas:
                                portas_vistas.add(chave_conexao)
                                prompt = f"""<|user|>
[CONTEXTO DE ANÁLISE]
Você é um Analista de Redes SOC. Avalie se esta conexão ativa estabelecida para fora da rede local representa tráfego malicioso.
- Aplicativo: {nome_proc}
- IP de Destino: {ip_remoto}

[FORMATO DE RESPOSTA]
Inicie com o veredito em negrito (**Perigo Detectado** ou **Seguro**), justificando em até 300 caracteres.<|end|>
<|assistant|>"""
                                r = requests.post("http://127.0.0.1:8000/v1/completions", json={"prompt": prompt, "max_tokens": 300, "temperature": 0.1})
                                texto = r.json()['choices'][0]['text'].strip()

                                if app_ui:
                                    app_ui.add_log_processo(f"Conexão ({ip_remoto})", texto)
                                    texto_lower = texto.lower()
                                    termos_reais_perigo = ["backdoor", "trojan", "malware", "ransomware", "exploit", "exfiltração de dados", "command and control"]
                                    tem_perigo_real = any(termo in texto_lower for termo in termos_reais_perigo)
                                    e_seguro = "seguro" in texto_lower or "legítimo" in texto_lower or "não é" in texto_lower
                                    
                                    if tem_perigo_real and not e_seguro:
                                        registrar_log_forense("CONEXAO_EXTERNA_SUSPEITA", {"processo": nome_proc, "ip": ip_remoto, "ia": texto})
                                        app_ui.after(0, lambda np=nome_proc, ip=ip_remoto, pr=porta_remota, t=texto: app_ui.mostrar_alerta_bloqueio("🚨 CONEXÃO MALICIOSA CONFIRMADA!", f"Processo: {np}\nIP Remoto: {ip}\n\nAnálise:\n{t}"))
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            print(f"❌ Erro no loop de rede: {e}", flush=True)
        time.sleep(2)

def loop_processos():
    treinar_baseline_inicial()
    observer_downloads = Observer()
    observer_downloads.schedule(MonitorArquivos(tipo="download"), PASTA_DOWNLOADS, recursive=False)
    observer_downloads.start()
    
    observers_sistema = []
    for pasta in PASTAS_SISTEMA_CRITICAS:
        if os.path.exists(pasta):
            obs = Observer()
            obs.schedule(MonitorArquivos(tipo="sistema"), pasta, recursive=True)
            obs.start()
            observers_sistema.append(obs)
            
    processos_ativos = {}
    while True:
        try:
            pids_atuais = set()
            for p in psutil.process_iter(['pid', 'name', 'memory_percent']):
                try:
                    pid = p.info['pid']
                    nome = p.info['name']
                    pids_atuais.add(pid)
                    
                    try:
                        cmdline_temp = " ".join(p.cmdline()) if p.cmdline() else ""
                    except:
                        cmdline_temp = ""

                    if nome and not is_whitelisted(nome, cmdline_temp):
                        mem = p.info['memory_percent'] or 0.0
                        if pid not in processos_ativos:
                            processos_ativos[pid] = p
                            p.cpu_percent(interval=None)
                            continue
                        cpu = processos_ativos[pid].cpu_percent(interval=None) or 0.0
                        try:
                            proc_obj = processos_ativos[pid]
                            cmdline = " ".join(proc_obj.cmdline()) if proc_obj.cmdline() else "Argumentos vazios"
                            path_binario = proc_obj.exe() if proc_obj.exe() else "Desconhecido"
                            pai = proc_obj.parent()
                            pai_nome = pai.name() if pai else "Systemd"
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            cmdline, path_binario, pai_nome = "Acesso Negado", "Acesso Negado", "Desconhecido"
                        analisar_comportamento_processo(nome, cpu, mem, cmdline, path_binario, pai_nome)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            pids_mortos = set(processos_ativos.keys()) - pids_atuais
            for pid in pids_mortos: 
                del processos_ativos[pid]
        except Exception: 
            pass
        time.sleep(15)

# ==========================================
# BANDEJA DE SISTEMA (SYSTEM TRAY)
# ==========================================
def tray_thread_func():
    if os.path.exists(CAMINHO_ICONE_PADRAO):
        imagem_tray = Image.open(CAMINHO_ICONE_PADRAO)
    else:
        print(f"⚠️ Aviso: {CAMINHO_ICONE_PADRAO} não encontrado para a bandeja. Usando fallback.")
        imagem_tray = Image.new('RGB', (64, 64), color='green')

    menu = pystray.Menu(
        pystray.MenuItem('Restaurar Painel', lambda: app_ui.mostrar_janela() if app_ui else None, default=True), 
        pystray.MenuItem('Sair', lambda icon: (icon.stop(), app_ui.sair_completo() if app_ui else os._exit(0)))
    )
    
    icone = pystray.Icon("cybersec", imagem_tray, "Neural CyberSec", menu)
    icone.run()


class CopilotoApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Neural CyberSec")
        self.geometry("900x650")
        self.attributes("-zoomed", True)
        self.withdraw()
        
        # 🛡️ Define o ícone personalizado (icone5.png) para a janela e barra de tarefas
        try:
            if os.path.exists(CAMINHO_ICONE_PADRAO):
                img_pil_custom = Image.open(CAMINHO_ICONE_PADRAO)
                self._icone_tk = ImageTk.PhotoImage(img_pil_custom)
                self.iconphoto(True, self._icone_tk)

            else:
                print(f"⚠️ Arquivo de ícone não encontrado em: {CAMINHO_ICONE_PADRAO}")

        except Exception as e:
            print(f"Erro ao definir ícone da janela: {e}")
        
        # Ao fechar pelo "X", apenas minimiza para a bandeja
        self.protocol("WM_DELETE_WINDOW", self.sair_completo)
        
        self.tabview = ctk.CTkTabview(self)
        self.tabview.pack(padx=20, pady=20, fill="both", expand=True)
        
        self.tabview._segmented_button.configure(
            font=("Arial", 26, "bold"),
            corner_radius=8,
            fg_color="#121a12",
            selected_color="#086D32",
            selected_hover_color="#007D40",
            unselected_color="#1e2e1e",
            unselected_hover_color="#2e4a2e"
        )
        
        self.aba_chat = self.tabview.add("Análise & Chat")
        self.aba_downloads = self.tabview.add("Downloads & Vírus")
        self.aba_logs = self.tabview.add("Logs de Processos")
        self.aba_whitelist = self.tabview.add("Whitelist")

        self.setup_aba_chat()
        self.setup_aba_downloads()
        self.setup_aba_logs()
        self.setup_aba_whitelist()

    def mostrar_janela(self):
        self.after(0, self.deiconify)

    def sair_completo(self):
        if os.path.exists(ARQUIVO_LOCK):
            try:
                os.remove(ARQUIVO_LOCK)
            except:
                pass
        os._exit(0)

    def tornar_copiavel(self, textbox):
        def copiar_selecao(event):
            try:
                selecao = textbox.get("sel.first", "sel.last")
                pyperclip.copy(selecao)
            except Exception:
                pass
            return "break"
        textbox.bind("<Control-c>", copiar_selecao)
        textbox.bind("<Control-C>", copiar_selecao)
        textbox.bind("<Key>", lambda e: "break")

    def setup_aba_chat(self):
        self.chat_history = ctk.CTkTextbox(self.aba_chat, font=FONTE_TEXTO, wrap="word", corner_radius=8)
        self.chat_history.pack(padx=15, pady=(15, 10), fill="both", expand=True)
        self.tornar_copiavel(self.chat_history)

        frame_botoes = ctk.CTkFrame(self.aba_chat, fg_color="transparent")
        frame_botoes.pack(padx=15, pady=15, fill="x")

        self.entrada_chat = ctk.CTkEntry(frame_botoes, placeholder_text="Pergunte algo à IA ou cole um link...", font=FONTE_TEXTO, height=40, corner_radius=8)
        self.entrada_chat.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.entrada_chat.bind("<Return>", lambda e: self.enviar_msg_chat())

        btn_enviar = ctk.CTkButton(frame_botoes, text="Enviar", command=self.enviar_msg_chat, width=100, height=40, font=FONTE_BOTAO, corner_radius=8, fg_color="#2b6cb0", hover_color="#2c5282")
        btn_enviar.pack(side="left", padx=(0, 10))

        btn_clipboard = ctk.CTkButton(frame_botoes, text="🔗 Testar Link", command=self.testar_link_copiado, height=40, font=FONTE_BOTAO, corner_radius=8, fg_color="#2f855a", hover_color="#276749")
        btn_clipboard.pack(side="right", padx=(0, 10))

        btn_print = ctk.CTkButton(frame_botoes, text="📷 Analisar Tela", command=self.analisar_tela, height=40, font=FONTE_BOTAO, corner_radius=8, fg_color="#c53030", hover_color="#9b2c2c")
        btn_print.pack(side="right")

    def add_chat_msg(self, autor, msg):
        self.chat_history.configure(state="normal")
        self.chat_history.insert("end", f"[{autor}]: {msg}\n\n")
        self.chat_history.see("end")
        self.chat_history.configure(state="disabled")

    def enviar_msg_chat(self):
        msg = self.entrada_chat.get()
        if not msg.strip(): return
        self.entrada_chat.delete(0, "end")
        self.add_chat_msg("Você", msg)
        threading.Thread(target=self.consultar_ia, args=(msg,)).start()

    def _analisar_url_thread(self, texto_url):
        try:
            risco_heuro, motivo_heuro = avaliar_heuristica_url(texto_url)
            parsed_url = urlparse(texto_url)
            dominio = parsed_url.netloc if parsed_url.netloc else parsed_url.path.split('/')[0]

            prompt = f"""<|user|>
Analise esta URL como SOC Analyst. Verifique se há phishing real ou engenharia social.
- URL: {texto_url}
- Domínio: {dominio}
- Heurística: {motivo_heuro}

Responda em PT-BR (máx 2 linhas): Inicie com **Perigo Detectado** ou **Seguro**.<|end|>
<|assistant|>"""

            resposta_ia = consultar_llama_local(prompt, max_tokens=150, temperature=0.1)
            self.after(0, lambda: self.add_chat_msg("IA", resposta_ia))
        except Exception as e:
            self.after(0, lambda: self.add_chat_msg("Erro", f"Falha na análise da URL: {e}"))

    def testar_link_copiado(self):
        try:
            link = pyperclip.paste().strip()
            if link:
                self.add_chat_msg("Você (Link Manual)", link)
                threading.Thread(target=self._analisar_url_thread, args=(link,)).start()
            else:
                self.add_chat_msg("Sistema", "A área de transferência está vazia.")
        except Exception as e:
            self.add_chat_msg("Erro", f"Não foi possível ler a área de transferência: {e}")

    def analisar_tela(self):
        self.withdraw()
        self.add_chat_msg("Sistema", "Minimizando temporariamente para ler o conteúdo da tela ativa...")
        self.after(1000, lambda: threading.Thread(target=self._processar_print_escondido).start())

    def _processar_print_escondido(self):
        try:
            with mss.mss() as sct:
                img = sct.grab(sct.monitors[1])
                img_pil = Image.frombytes("RGB", img.size, img.bgra, "raw", "BGRX")
            
            self.after(0, self.mostrar_janela)
            
            texto_tela = pytesseract.image_to_string(img_pil, lang='por')
            if not texto_tela.strip():
                self.after(0, lambda: self.add_chat_msg("IA", "Não encontrei nenhum texto legível na tela ativa."))
                return
            
            prompt = f"""<|user|>
[CONTEXTO DE ANÁLISE VISUAL / CHAT]
Analise o texto extraído da tela (mensagens de chat, conversas ou links visíveis):
{texto_tela[:1500]}

Avalie se há tentativas de golpe, phishing, engenharia social ou chaves/links maliciosos.
Responda em PT-BR: Inicie com **Seguro** ou **Perigo Detectado**, seguido de uma explicação curta.<|end|>
<|assistant|>"""
            
            threading.Thread(target=self._consultar_ia_direto, args=(prompt,)).start()
        except Exception as e:
            self.after(0, self.mostrar_janela)
            self.after(0, lambda: self.add_chat_msg("Erro", f"Falha no OCR da tela: {e}"))

    def _consultar_ia_direto(self, prompt_completo):
        try:
            r = requests.post("http://127.0.0.1:8000/v1/completions", json={"prompt": prompt_completo, "max_tokens": 300, "temperature": 0.1})
            texto_ia = r.json()['choices'][0]['text'].strip()
            self.after(0, lambda: self.add_chat_msg("IA", texto_ia))
        except Exception:
            self.after(0, lambda: self.add_chat_msg("Erro", "Falha de conexão com servidor Llama local."))

    def consultar_ia(self, prompt_usuario):
        prompt = f"<|user|>\n{prompt_usuario}<|end|>\n<|assistant|>"
        try:
            r = requests.post("http://127.0.0.1:8000/v1/completions", json={"prompt": prompt, "max_tokens": 800, "temperature": 0.2})
            texto_ia = r.json()['choices'][0]['text'].strip()
            self.after(0, lambda: self.add_chat_msg("IA", texto_ia))
        except Exception:
            self.after(0, lambda: self.add_chat_msg("Erro", "Falha de conexão com servidor Llama local."))

    def setup_aba_downloads(self):
        lbl_info = ctk.CTkLabel(self.aba_downloads, text="Histórico de verificação de arquivos baixados:", font=FONTE_TEXTO)
        lbl_info.pack(padx=10, pady=(10, 0), anchor="w")
        self.caixa_downloads = ctk.CTkTextbox(self.aba_downloads, font=FONTE_TEXTO, wrap="word", fg_color="#1e1e1e", text_color="#aaaaaa")
        self.caixa_downloads.pack(padx=10, pady=10, fill="both", expand=True)
        self.tornar_copiavel(self.caixa_downloads)

    def add_log_download(self, nome_arquivo, status):
        self.caixa_downloads.configure(state="normal")
        hora = time.strftime("%H:%M:%S")
        self.caixa_downloads.insert("end", f"[{hora}] 📄 {nome_arquivo}\nStatus: {status}\n{'-'*60}\n")
        self.caixa_downloads.see("end")
        self.caixa_downloads.configure(state="disabled")

    def setup_aba_logs(self):
        lbl_info = ctk.CTkLabel(self.aba_logs, text="Histórico Forense de Processos, Rede e Anomalias:", font=FONTE_TEXTO)
        lbl_info.pack(padx=10, pady=(10, 5), anchor="w")
        self.frame_tabela = ctk.CTkScrollableFrame(self.aba_logs, fg_color="#1e1e1e")
        self.frame_tabela.pack(padx=10, pady=10, fill="both", expand="True")
        
        headers = ["Hora", "Tipo/Processo", "Análise Forense do Copiloto (Llama 3 Local)"]
        widths = [100, 460, 560]
        frame_header = ctk.CTkFrame(self.frame_tabela, fg_color="#2b2b2b")
        frame_header.pack(fill="x", pady=(0, 5))
        for i, h in enumerate(headers):
            lbl = ctk.CTkLabel(frame_header, text=h, font=("Arial", 20, "bold"), text_color="#00ff7f", width=widths[i], anchor="w")
            lbl.pack(side="left", padx=10, pady=5)

    def add_log_processo(self, nome_processo, texto_ia):
        self.after(0, lambda: self._add_log_processo_interface(nome_processo, texto_ia))

    def _add_log_processo_interface(self, nome_processo, texto_ia):
        hora = time.strftime("%H:%M:%S")
        fg_linha = "#0d2111" if "seguro" in texto_ia.lower() else "#1a241b"
        
        frame_linha = ctk.CTkFrame(self.frame_tabela, fg_color=fg_linha, corner_radius=6)
        frame_linha.pack(fill="x", pady=6, padx=5)
        
        lbl_hora = ctk.CTkLabel(frame_linha, text=hora, font=("Segoe UI", 20), text_color="#EFEFEF", width=80, anchor="w")
        lbl_hora.pack(side="left", padx=8, pady=10)
        
        btn_nome_caixa = ctk.CTkButton(
            frame_linha,
            text=nome_processo,
            font=("Segoe UI", 20, "bold"),
            text_color="#ffffff",
            fg_color="#0f2e1a",
            hover_color="#0f2e1a",
            corner_radius=8,
            width=260,
            height=50,
            state="disabled"
        )
        btn_nome_caixa.pack(side="left", padx=8, pady=10)
        
        txt_analise = ctk.CTkTextbox(frame_linha, font=("Segoe UI", 20), text_color="#00ff7f" if "seguro" in texto_ia.lower() else "#cccccc", fg_color="transparent", height=350, wrap="word")
        txt_analise.pack(side="left", fill="x", expand=True, padx=8, pady=10)
        txt_analise.insert("0.0", texto_ia.strip())
        txt_analise.configure(state="disabled")
        self.tornar_copiavel(txt_analise)
        
        def copiar_este_log():
            conteudo = f"[{hora}] {nome_processo}: {texto_ia.strip()}"
            pyperclip.copy(conteudo)
            self.mostrar_toast("✅ Copiado!", f"Log copiado para a área de transferência.", "#00ff00")

        btn_copiar_linha = ctk.CTkButton(frame_linha, text="📋 Copiar", width=80, height=35, font=("Segoe UI", 18, "bold"), fg_color="#1f538d", hover_color="#14375e", command=copiar_este_log)
        btn_copiar_linha.pack(side="right", padx=8, pady=10)

    def setup_aba_whitelist(self):
        frame_top = ctk.CTkFrame(self.aba_whitelist, fg_color="transparent")
        frame_top.pack(padx=10, pady=10, fill="x")
        self.entrada_wl = ctk.CTkEntry(frame_top, placeholder_text="Nome do processo", font=FONTE_TEXTO)
        self.entrada_wl.pack(side="left", fill="x", expand=True, padx=(0, 10))
        btn_add = ctk.CTkButton(frame_top, text="Adicionar", command=self.add_whitelist, width=100, font=FONTE_BOTAO)
        btn_add.pack(side="left")
        self.lista_wl = ctk.CTkTextbox(self.aba_whitelist, font=FONTE_TEXTO)
        self.lista_wl.pack(padx=10, pady=10, fill="both", expand=True)
        self.tornar_copiavel(self.lista_wl)
        self.atualizar_lista_wl()

    def atualizar_lista_wl(self):
        self.lista_wl.configure(state="normal")
        self.lista_wl.delete("0.0", "end")
        self.lista_wl.insert("end", "\n".join(sorted(WHITELIST)))
        self.lista_wl.configure(state="disabled")

    def add_whitelist(self):
        global WHITELIST
        processo = self.entrada_wl.get().strip()
        if processo and processo not in WHITELIST:
            WHITELIST.append(processo)
            salvar_whitelist(WHITELIST)
            self.entrada_wl.delete(0, "end")
            self.atualizar_lista_wl()

    def mostrar_toast(self, titulo, message, cor_borda="#00ff00"):
        toast = ctk.CTkToplevel(self)
        toast.overrideredirect(True)
        toast.attributes("-topmost", True)
        frame = ctk.CTkFrame(toast, border_width=2, border_color=cor_borda, fg_color="#1a1a1a")
        frame.pack(fill="both", expand=True)
        lbl_titulo = ctk.CTkLabel(frame, text=titulo, font=("Arial", 20, "bold"), text_color="white")
        lbl_titulo.pack(padx=15, pady=(15, 5), anchor="w")
        lbl_msg = ctk.CTkLabel(frame, text=message, font=("Arial", 18), justify="left", wraplength=400)
        lbl_msg.pack(padx=15, pady=(0, 15), anchor="w")
        toast.update_idletasks()
        w, h = toast.winfo_width(), toast.winfo_height()
        ws, hs = toast.winfo_screenwidth(), toast.winfo_screenheight()
        x = ws - w - 20
        y = hs - h - 50
        toast.geometry(f"+{x}+{y}")
        self.after(8000, toast.destroy)

    def mostrar_alerta_bloqueio(self, titulo, mensagem):
        alerta = ctk.CTkToplevel(self)
        alerta.overrideredirect(True)
        alerta.attributes("-topmost", True)
        w, h = 800, 500
        ws = alerta.winfo_screenwidth()
        hs = alerta.winfo_screenheight()
        x = (ws // 2) - (w // 2)
        y = (hs // 2) - (h // 2)
        alerta.geometry(f"{w}x{h}+{x}+{y}")
        frame = ctk.CTkFrame(alerta, border_width=6, border_color="#ff0000", fg_color="#2b0000")
        frame.pack(fill="both", expand=True)
        lbl_titulo = ctk.CTkLabel(frame, text=titulo, font=("Arial", 32, "bold"), text_color="#ff4444")
        lbl_titulo.pack(padx=20, pady=(25, 10))
        txt_msg = ctk.CTkTextbox(frame, font=("Arial", 20), text_color="white", fg_color="#1a0000", wrap="word")
        txt_msg.pack(padx=20, pady=10, fill="both", expand=True)
        txt_msg.insert("0.0", mensagem)
        txt_msg.configure(state="disabled")
        btn_fechar = ctk.CTkButton(frame, text="ESTOU CIENTE (FECHAR)", fg_color="#ff0000", hover_color="#aa0000", font=("Arial", 18, "bold"), command=alerta.destroy)
        btn_fechar.pack(pady=20)

if __name__ == "__main__":
    verificar_instancia_unica()
    app_ui = CopilotoApp()
    threading.Thread(target=tray_thread_func, daemon=True).start()
    threading.Thread(target=loop_processos, daemon=True).start()
    threading.Thread(target=loop_clipboard, daemon=True).start()
    threading.Thread(target=loop_monitor_rede, daemon=True).start()
    try:
        app_ui.mainloop()
    finally:
        if os.path.exists(ARQUIVO_LOCK):
            os.remove(ARQUIVO_LOCK)
