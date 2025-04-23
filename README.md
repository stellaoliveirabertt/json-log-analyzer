# JSON Log Analyzer 🔍📊

Uma ferramenta interativa para análise automatizada de logs no formato JSON, com interface web intuitiva e geração de relatórios explicativos. Ideal para desenvolvedores, times de suporte e analistas que desejam identificar rapidamente problemas, exceções e padrões em aplicações modernas.

---

## ✨ Funcionalidades

- Upload e análise de arquivos `.json` ou `.txt` com logs estruturados
- Detecção de exceções e sugestões de resolução
- Identificação de padrões comuns de falhas (ex: `Timeout`, `OutOfMemory`, `Unauthorized`)
- Análise de componentes e métodos envolvidos
- Geração de relatórios legíveis com:
  - Severidade do evento
  - Categoria e Trace IDs
  - Stack trace analisado
  - Sugestões técnicas e recomendações
- Interface web responsiva em HTML + CSS
- Endpoint adicional para análise via JSON direto (API)

---

## 🚀 Como usar

### 1. Clone o repositório
```bash
git clone https://github.com/stellaoliveirabertt/json-log-analyzer.git
cd json-log-analyzer
```

### 2. Crie o ambiente virtual e instale as dependências
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Inicie a aplicação
```bash
python app.py
```

### 4. Acesse via navegador
Acesse `http://localhost:5001` no seu navegador para utilizar a interface web.

---

## 📂 Estrutura do Projeto

- `app.py`: Interface Flask para upload e envio JSON
- `log_analyzer.py`: Lógica principal de análise e relatórios
- `templates/index.html`: Frontend da aplicação
- `static/`: Estilos e scripts
- `test_log.json`: Exemplo de entrada

---

## 🧠 Tecnologias

- Python 3.9+
- Flask
- HTML/CSS Vanilla
- Análise de logs baseada em padrões (com auxílio do Manus)

---

## 🧑‍💻 Autoria

Desenvolvido com 💙 por [@stellaoliveirabertt](https://github.com/stellaoliveirabertt)

---

## 📄 Licença

MIT License. Veja o arquivo `LICENSE` para mais detalhes.
