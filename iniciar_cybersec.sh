#!/bin/bash

# Garante que o diretório de trabalho seja exatamente onde o script está localizado
cd "$(dirname "$(readlink -f "$0")")"

echo "🛡️ [Neural CyberSec] Iniciando verificação..."

# 1. Verifica se o modelo GGUF existe na pasta atual
if [ ! -f "./Meta-Llama-3-8B-Instruct.Q4_K_M.gguf" ]; then
    echo "❌ ERRO: O arquivo do modelo Llama não foi encontrado nesta pasta!"
    echo "Caminho esperado: $(pwd)/Meta-Llama-3-8B-Instruct.Q4_K_M.gguf"
    read -p "Pressione [ENTER] para sair..."
    exit 1
fi

# 2. Verifica se a porta 8000 já está em uso (servidor rodando)
if ss -tlnp 2>/dev/null | grep -q ":8000 "; then
    echo "✅ O servidor Llama já está rodando na porta 8000!"
else
    echo "🚀 Iniciando o servidor Llama na RX 580..."
    python3 -m llama_cpp.server \
        --model ./Meta-Llama-3-8B-Instruct.Q4_K_M.gguf \
        --n_gpu_layers -1 \
        --n_ctx 4096 \
        --n_batch 1024 \
        --host 127.0.0.1 \
        --port 8000 > server.log 2>&1 &
    
    echo "⏳ Aguardando o servidor subir na VRAM..."
    sleep 4
fi

# 3. Inicia o aplicativo principal usando o Python do ambiente virtual (.venv)
if [ -f "./.venv/bin/python3" ]; then
    echo "🚀 Iniciando o painel Neural CyberSec (via .venv)..."
    ./.venv/bin/python3 agente_monitor_v3.py
elif [ -f "./venv/bin/python3" ]; then
    echo "🚀 Iniciando o painel Neural CyberSec (via venv)..."
    ./venv/bin/python3 agente_monitor_v3.py
else
    echo "🚀 Iniciando o painel Neural CyberSec..."
    python3 agente_monitor_v3.py
fi