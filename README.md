🛡️ Neural CyberSec

O Neural CyberSec é uma solução EDR (Endpoint Detection and Response) local e open-source desenvolvida em Python. O projeto integra Machine Learning, análise comportamental e Inteligência Artificial local via Llama 3 para proteger sistemas Linux e Windows contra malware, modificações não autorizadas no sistema, conexões de rede suspeitas e tentativas de phishing.

🚀 Principais Funcionalidades

🤖 Análise Comportamental com IA Local (Llama 3):

Monitoriza o uso de CPU e RAM dos processos em tempo real utilizando IsolationForest (Machine Learning).

Caso um processo apresente comportamento anómalo, o Llama 3 (executado localmente via llama.cpp) analisa o risco e decide se aciona um Alerta Vermelho.

📄 Quarentena Ativa e Verificação de Downloads (VirusTotal):

Monitoriza a pasta de Downloads continuamente através do watchdog.

Calcula o hash SHA-256 dos novos ficheiros e consulta a API do VirusTotal.

Quarentena Automática: Se um malware for detetado, o ficheiro é movido de imediato para uma pasta isolada e segura (quarentena/), tendo as suas permissões de execução totalmente revogadas.

🚪 Monitor de Rede e Portas (Locais e Externas):

Inspeciona portas de escuta (LISTEN) para detetar potenciais aplicações não autorizadas ou backdoors.

Monitoriza conexões ativas estabelecidas com endereços IP remotos externos (ESTABLISHED) para identificar potenciais comunicações com servidores de comando e controlo (C2).

📁 Proteção de Pastas Críticas do Sistema:

Vigia diretórios vitais do sistema operativo (como /etc no Linux ou System32 no Windows) contra alterações não autorizadas.

📋 Monitor Inteligente de Clipboard & OCR (Análise de Tela):

Lê links copiados para a área de transferência e recorre à IA para identificar tentativas de phishing ou golpes.

Extrai texto do ecrã em tempo real através de OCR (pyesseract) para auditar possíveis comandos ou conteúdos maliciosos visíveis.

Botão Analisar Tela - ao clicar, a interface do aplicativo desaparece por um segundo para capturar a tela aberta. Pode ser qualquer aplicativo que esteja visível no momento da captura. Analisa a tela e indica se há algum risco de segurança. Permite conversar no chat com o modelo de IA e até treinar o modelo, concordando ou discordando de sua análise.

📊 Registo Forense Estruturado:

Regista todos os eventos críticos de segurança (como deteções, ativações de quarentena e acessos de rede) num diário de auditoria em formato JSON (forense.json).

🎛️ Interface Gráfica e System Tray:

Interface limpa desenvolvida em customtkinter com modo escuro e sistema de abas.

Ícone vetorial estilizado em alta definição na bandeja do sistema (System Tray).



## 🛠️ Pré-requisitos e Dependências

* **Python 3.10+** instalado no sistema.
  
* **Placa de Vídeo (GPU):** Recomenda-se uma GPU dedicada com **no mínimo 8 GB de VRAM** para carregar e executar o modelo Llama 3 8B localmente com boa performance.
  
* **Tesseract-OCR** instalado (necessário para a função de OCR/análise de tela):
  
  * *Linux:* `sudo apt install tesseract-ocr tesseract-ocr-por`
    
  * *Windows:* Baixe o instalador oficial e adicione ao PATH do sistema.
    
* Um modelo **Llama 3 (.gguf)** configurado para rodar localmente com `llama-cpp-python` ou `llama.cpp`.
  
* Uma chave de API gratuita do **VirusTotal** (para a verificação de hash de ficheiros descarregados).


📦 Instalação

Clona o repositório para a tua máquina:

git clone https://github.com/o-teu-utilizador/copilot_cybersec.git
cd copilot_cybersec


Cria e ativa um ambiente virtual Python:

python3 -m venv venv
source venv/bin/activate


Instala todas as dependências listadas no projeto:

pip install -r requirements.txt


Configura as tuas variáveis de ambiente:
Cria um ficheiro chamado .env na raiz do projeto e adiciona a tua chave do VirusTotal:

VIRUSTOTAL_API_KEY=a_tua_chave_aqui


🐧 Criar Atalho no Menu de Aplicações (Linux / Linux Mint)

Para adicionar o procedimento de criação do atalho no menu de aplicativos do Linux Mint / Cinnamon no seu README (considerando que o script iniciar_cybersec.sh já faz parte do repositório clonado), você pode utilizar este trecho:

Markdown
### Criar Atalho no Menu de Aplicativos (Linux / Linux Mint)

Para integrar o **Neural CyberSec** diretamente no menu do seu sistema e na barra de tarefas com o ícone personalizado (`icone5.png`), siga os passos abaixo:

1. **Criar o arquivo de atalho do usuário:**
   Abra o terminal e crie o ficheiro `.desktop` na pasta de aplicações locais:
   ```bash
   nano ~/.local/share/applications/neural_cybersec.desktop
Colar a configuração:
Cole o conteúdo abaixo no ficheiro (substitua /home/seu-usuario/copilot_cybersec pelo caminho real onde clonou o repositório):

Ini, TOML
[Desktop Entry]
Version=1.0
Type=Application
Name=Neural CyberSec
Comment=Proteção e Copiloto de IA Local com Llama 3
Exec=/home/seu-usuario/copilot_cybersec/iniciar_cybersec.sh
Icon=/home/seu-usuario/copilot_cybersec/icone5.png
Terminal=false
Categories=Utility;Security;System;


Dar permissão de execução:
Torne o atalho confiável para o sistema executando no terminal:

Bash
chmod +x ~/.local/share/applications/neural_cybersec.desktop

🚀 Como Executar

Execução Manual

Podes iniciar o servidor do Llama e o agente de monitoramento através do script de inicialização integrado:

./iniciar_cybersec.sh




### 📦 Instalação no Windows


1. **Clonar o Repositório:**
   Abra o seu terminal (Git Bash ou Prompt de Comando) e clone o repositório para a sua máquina:
   ```cmd
   git clone [https://github.com/o-teu-utilizador/copilot_cybersec.git](https://github.com/o-teu-utilizador/copilot_cybersec.git)
   cd copilot_cybersec
Criar e Ativar o Ambiente Virtual:

DOS
python -m venv venv
venv\Scripts\activate
Instalar as Dependências:
Instale todas as bibliotecas necessárias listadas no projeto:

DOS
pip install -r requirements.txt
Instalar o Tesseract-OCR (Essencial para a Análise de Tela/OCR):

Transfira e execute o instalador oficial do Tesseract para Windows (disponibilizado pela UB Mannheim no GitHub).

Certifique-se de adicionar o caminho de instalação do Tesseract às Variáveis de Ambiente (PATH) do Windows durante o processo.

Configurar as Variáveis de Ambiente:
Crie um ficheiro chamado .env na raiz do projeto e insira a sua chave de API do VirusTotal:

Snippet de código
VIRUSTOTAL_API_KEY=a_tua_chave_aqui
Descarregar o Modelo Llama 3:
Coloque o ficheiro de pesos do modelo (Meta-Llama-3-8B-Instruct.Q4_K_M.gguf) diretamente na raiz da pasta do projeto.

🚀 Como Executar e Inicializar no Windows
Para facilitar a inicialização de todo o ecossistema (servidor local Llama e painel EDR em segundo plano) com apenas um clique:

Criar o Script de Inicialização (iniciar_cybersec.bat):
Na raiz da pasta do projeto, crie um ficheiro chamado iniciar_cybersec.bat com o seguinte código:


@echo off
cd /d "%~dp0"
start /b python -m llama_cpp.server --model ./Meta-Llama-3-8B-Instruct.Q4_K_M.gguf --n_gpu_layers -1 --n_ctx 4096 --n_batch 1024 --host 127.0.0.1 --port 8000 > server.log 2>&1
timeout /t 4 /nobreak > nul
start /b python agente_monitor_v3.py > agente.log 2>&1
exit
Criar um Atalho na Área de Trabalho com Ícone Personalizado:

Clique com o botão direito do rato no ficheiro iniciar_cybersec.bat.

Selecione Enviar para > Área de trabalho (criar atalho).

Clique com o botão direito no atalho criado na área de trabalho, vá em Propriedades, selecione Alterar Ícone... e aponte para o ficheiro icone5.png do projeto para utilizar o escudo personalizado com a letra "N".


🤝 Contribuições

Contribuições, sugestões de melhorias e novas funcionalidades são sempre bem-vindas! Siste-te à vontade para abrir uma Issue ou enviar um Pull Request.

📜 Licença

Este projeto é distribuído sob a licença MIT. Consulta o ficheiro LICENSE para mais detalhes.
