#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Interface para Analisador de Logs JSON

Esta ferramenta fornece uma interface web simples para submeter arquivos de log JSON
e visualizar análises explicativas sobre o conteúdo dos logs.
"""

import os
import json
import tempfile
from flask import Flask, request, render_template, jsonify
from werkzeug.utils import secure_filename
from log_analyzer import LogAnalyzer, load_json_log

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limite de 16MB para upload
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()

@app.route('/')
def index():
    """Renderiza a página inicial."""
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    """
    Endpoint para analisar um arquivo de log JSON enviado pelo usuário.
    
    Returns:
        Resposta JSON com o resultado da análise ou mensagem de erro
    """
    # Verificar se há arquivo na requisição
    if 'file' not in request.files:
        return jsonify({'error': 'Nenhum arquivo enviado'}), 400
    
    file = request.files['file']
    
    # Verificar se o usuário selecionou um arquivo
    if file.filename == '':
        return jsonify({'error': 'Nenhum arquivo selecionado'}), 400
    
    # Verificar extensão do arquivo
    if not file.filename.endswith(('.json', '.txt')):
        return jsonify({'error': 'Formato de arquivo não suportado. Use arquivos .json ou .txt'}), 400
    
    try:
        # Salvar o arquivo temporariamente
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Analisar o arquivo
        log_data = load_json_log(filepath)
        analyzer = LogAnalyzer(log_data)
        analysis = analyzer.analyze()
        report = analyzer.generate_report()
        
        # Remover o arquivo temporário
        os.remove(filepath)
        
        # Retornar o resultado
        return jsonify({
            'success': True,
            'report': report,
            'analysis': analysis
        })
    
    except Exception as e:
        # Garantir que o arquivo temporário seja removido em caso de erro
        if 'filepath' in locals() and os.path.exists(filepath):
            os.remove(filepath)
        
        return jsonify({'error': str(e)}), 500

@app.route('/analyze-json', methods=['POST'])
def analyze_json_content():
    """
    Endpoint para analisar conteúdo JSON enviado diretamente.
    
    Returns:
        Resposta JSON com o resultado da análise ou mensagem de erro
    """
    try:
        # Obter o conteúdo JSON do corpo da requisição
        content = request.json
        
        if not content:
            return jsonify({'error': 'Nenhum conteúdo JSON enviado'}), 400
        
        # Analisar o conteúdo
        analyzer = LogAnalyzer(content)
        analysis = analyzer.analyze()
        report = analyzer.generate_report()
        
        # Retornar o resultado
        return jsonify({
            'success': True,
            'report': report,
            'analysis': analysis
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Criar diretório de templates se não existir
    templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    # Iniciar o servidor
    app.run(host='0.0.0.0', port=5001, debug=True)
