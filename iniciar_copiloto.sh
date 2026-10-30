#!/bin/bash

# Entra na pasta do projeto
cd ~/copilot_cybersec

# Ativa o ambiente virtual
source venv/bin/activate

# 1. Encerra qualquer instância anterior do servidor na porta 8000 para evitar conflito
fuser -k 8000/tcp > /dev/null 2>&1
sleep 1

echo "Iniciando o servidor Llama 3..."

# 2. Inicia o servidor do Llama em background na porta 8000
python -m llama_cpp.server --model ./Meta-Llama-3-8B-Instruct.Q4_K_M.gguf --n_gpu_layers -1 --n_ctx 4096 --n_batch 1024 --host 127.0.0.1 --port 8000 > server.log 2>&1 &
# 3. Aguarda 40 segundos (com base nos 33s medidos) para o modelo carregar totalmente
sleep 40

echo "Iniciando o Copiloto CyberSec..."

# 4. Inicia o agente de monitoramento
python agente_monitor.py

# Encerrar o servidor: pkill -f llama_cpp.server
