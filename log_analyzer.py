#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Analisador Avançado de Logs JSON

Esta ferramenta analisa arquivos de log em formato JSON e fornece informações
de forma breve e explicativa sobre o conteúdo dos logs, incluindo análises
detalhadas e recomendações.
"""

import json
import sys
import os
import re
import datetime
import hashlib
from typing import Dict, Any, List, Optional, Tuple, Set

# Mapeamento de níveis de log para descrições mais amigáveis
LOG_LEVELS = {
    0: "Trace",
    1: "Debug",
    2: "Information",
    3: "Warning",
    4: "Error",
    5: "Critical",
    6: "None"
}

# Mapeamento de níveis de log para severidade
LOG_SEVERITY = {
    0: "Baixa",
    1: "Baixa",
    2: "Média",
    3: "Média",
    4: "Alta",
    5: "Crítica",
    6: "Desconhecida"
}

# Padrões comuns de exceções e seus significados
EXCEPTION_PATTERNS = {
    "NullReferenceException": {
        "description": "Tentativa de acessar um objeto que é nulo",
        "recommendation": "Verifique se o objeto foi inicializado antes de acessá-lo. Considere usar o operador de verificação nula (?.) ou validar com condicionais."
    },
    "ArgumentNullException": {
        "description": "Um argumento nulo foi passado para um método que não aceita valores nulos",
        "recommendation": "Verifique os parâmetros passados para o método e garanta que valores não nulos sejam fornecidos."
    },
    "ArgumentException": {
        "description": "Um argumento inválido foi passado para um método",
        "recommendation": "Verifique os parâmetros passados para o método e garanta que valores válidos sejam fornecidos."
    },
    "InvalidOperationException": {
        "description": "Uma operação foi tentada em um estado inválido",
        "recommendation": "Verifique o estado do objeto antes de realizar a operação. Considere adicionar validações de estado."
    },
    "TimeoutException": {
        "description": "Uma operação excedeu o tempo limite",
        "recommendation": "Verifique a conectividade de rede, disponibilidade do serviço ou aumente o tempo limite da operação."
    },
    "IOException": {
        "description": "Erro de entrada/saída ao acessar arquivos ou recursos",
        "recommendation": "Verifique permissões de acesso, existência do arquivo/recurso e conectividade."
    },
    "DbException|SqlException": {
        "description": "Erro relacionado ao banco de dados",
        "recommendation": "Verifique a conexão com o banco de dados, a consulta SQL e os parâmetros fornecidos."
    },
    "JsonException": {
        "description": "Erro ao processar ou serializar JSON",
        "recommendation": "Verifique o formato do JSON e a compatibilidade com o modelo de dados esperado."
    },
    "HttpRequestException": {
        "description": "Erro ao fazer uma requisição HTTP",
        "recommendation": "Verifique a conectividade de rede, a URL e a disponibilidade do serviço."
    },
    "AuthenticationException": {
        "description": "Erro de autenticação",
        "recommendation": "Verifique as credenciais fornecidas e as permissões do usuário."
    },
    "UnauthorizedAccessException": {
        "description": "Acesso não autorizado a um recurso",
        "recommendation": "Verifique as permissões do usuário e do aplicativo para acessar o recurso."
    },
    "OutOfMemoryException": {
        "description": "Memória insuficiente para executar a operação",
        "recommendation": "Otimize o uso de memória, considere liberar recursos não utilizados ou aumentar a memória disponível."
    },
    "ThreadAbortException": {
        "description": "Uma thread foi abortada",
        "recommendation": "Investigue por que a thread foi abortada e considere usar mecanismos de cancelamento mais seguros."
    },
    "TaskCanceledException": {
        "description": "Uma tarefa assíncrona foi cancelada",
        "recommendation": "Verifique se o cancelamento foi intencional e trate adequadamente nos blocos catch."
    }
}

# Componentes comuns e suas descrições
COMMON_COMPONENTS = {
    "System": "Biblioteca padrão do .NET",
    "Microsoft": "Componentes da Microsoft",
    "Amazon": "AWS SDK ou serviços da Amazon",
    "wisecons": "Componente interno da aplicação",
    "DynamoDB": "Banco de dados NoSQL da AWS",
    "Http": "Componentes relacionados a requisições HTTP",
    "Json": "Componentes de processamento JSON",
    "Async": "Operações assíncronas",
    "Thread": "Operações relacionadas a threads",
    "Task": "Operações assíncronas baseadas em tarefas",
    "Exception": "Tratamento de exceções",
    "Runtime": "Ambiente de execução .NET",
    "Compiler": "Compilador .NET",
    "Reflection": "Reflexão .NET",
    "Serialization": "Serialização/Deserialização de dados",
    "Authentication": "Autenticação e autorização",
    "Authorization": "Controle de acesso e permissões"
}

class LogAnalyzer:
    """Classe para analisar e extrair informações de logs em formato JSON."""
    
    def __init__(self, log_data: Dict[str, Any]):
        """
        Inicializa o analisador com os dados do log.
        
        Args:
            log_data: Dicionário contendo os dados do log em formato JSON
        """
        self.log_data = log_data
        self.log_entry = self.log_data.get("Log", {})
        
    def get_basic_info(self) -> Dict[str, Any]:
        """
        Extrai informações básicas do log.
        
        Returns:
            Dicionário com informações básicas do log
        """
        timestamp = self.log_entry.get("Timestamp")
        formatted_time = None
        
        if timestamp:
            try:
                dt = datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                formatted_time = dt.strftime("%d/%m/%Y %H:%M:%S")
            except (ValueError, TypeError):
                formatted_time = timestamp
        
        log_level_num = self.log_entry.get("LogLevel")
        log_level = LOG_LEVELS.get(log_level_num, f"Desconhecido ({log_level_num})")
        severity = LOG_SEVERITY.get(log_level_num, "Desconhecida")
        
        return {
            "timestamp": formatted_time,
            "log_level": log_level,
            "severity": severity,
            "category": self.log_entry.get("CategoryName"),
            "span_id": self.log_entry.get("SpanId"),
            "trace_id": self.log_entry.get("TraceId"),
            "trace_flags": self.log_entry.get("TraceFlags")
        }
    
    def extract_message_info(self) -> Dict[str, Any]:
        """
        Extrai e analisa a mensagem formatada do log.
        
        Returns:
            Dicionário com informações extraídas da mensagem
        """
        message = self.log_entry.get("FormattedMessage", "")
        
        # Extrair a mensagem principal (antes do stack trace)
        main_message = message.split("at ", 1)[0].strip() if "at " in message else message
        
        # Identificar componentes principais no stack trace
        components = set()
        methods = set()
        
        # Padrão para encontrar namespaces e métodos
        namespace_pattern = r'at\s+([a-zA-Z0-9_.]+)\.([a-zA-Z0-9_]+)\('
        
        for match in re.finditer(namespace_pattern, message):
            namespace = match.group(1)
            method = match.group(2)
            
            # Adicionar apenas o componente de nível superior (primeiro segmento do namespace)
            if '.' in namespace:
                component = namespace.split('.')[0]
                components.add(component)
            else:
                components.add(namespace)
                
            methods.add(f"{namespace}.{method}")
        
        # Identificar arquivos e linhas mencionados
        files = set()
        file_pattern = r'in\s+(/[^\s:]+):line\s+(\d+)'
        
        for match in re.finditer(file_pattern, message):
            file_path = match.group(1)
            line_num = match.group(2)
            files.add(f"{file_path}:{line_num}")
        
        # Identificar exceções mencionadas
        exceptions = set()
        exception_pattern = r'([A-Za-z0-9_]+Exception)'
        
        for match in re.finditer(exception_pattern, message):
            exceptions.add(match.group(1))
        
        return {
            "main_message": main_message,
            "components": list(components),
            "key_methods": list(methods)[:5],  # Limitar a 5 métodos para não sobrecarregar
            "files": list(files),
            "exceptions": list(exceptions)
        }
    
    def identify_patterns(self, message_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Identifica padrões conhecidos no log.
        
        Args:
            message_info: Informações extraídas da mensagem
            
        Returns:
            Dicionário com padrões identificados
        """
        patterns = {
            "exception_info": [],
            "component_info": [],
            "potential_issues": []
        }
        
        # Analisar exceções
        for exception in message_info.get("exceptions", []):
            for pattern, info in EXCEPTION_PATTERNS.items():
                if re.search(pattern, exception):
                    patterns["exception_info"].append({
                        "exception": exception,
                        "description": info["description"],
                        "recommendation": info["recommendation"]
                    })
                    break
            else:
                # Se não encontrou um padrão conhecido
                patterns["exception_info"].append({
                    "exception": exception,
                    "description": "Exceção não categorizada",
                    "recommendation": "Analise o stack trace para entender o contexto da exceção."
                })
        
        # Analisar componentes
        for component in message_info.get("components", []):
            for known_component, description in COMMON_COMPONENTS.items():
                if known_component in component:
                    patterns["component_info"].append({
                        "component": component,
                        "description": description
                    })
                    break
            else:
                # Se não encontrou um componente conhecido
                patterns["component_info"].append({
                    "component": component,
                    "description": "Componente específico da aplicação"
                })
        
        # Identificar potenciais problemas
        main_message = message_info.get("main_message", "").lower()
        
        if "timeout" in main_message or "timed out" in main_message:
            patterns["potential_issues"].append({
                "issue": "Timeout",
                "description": "Uma operação excedeu o tempo limite",
                "recommendation": "Verifique a conectividade de rede, disponibilidade do serviço ou aumente o tempo limite da operação."
            })
        
        if "connection" in main_message and ("failed" in main_message or "error" in main_message):
            patterns["potential_issues"].append({
                "issue": "Falha de Conexão",
                "description": "Falha ao estabelecer conexão com um serviço ou recurso",
                "recommendation": "Verifique a conectividade de rede, disponibilidade do serviço e configurações de conexão."
            })
        
        if "memory" in main_message:
            patterns["potential_issues"].append({
                "issue": "Problema de Memória",
                "description": "Possível problema relacionado ao uso de memória",
                "recommendation": "Verifique o consumo de memória da aplicação e considere otimizações."
            })
        
        if "deadlock" in main_message:
            patterns["potential_issues"].append({
                "issue": "Deadlock",
                "description": "Possível deadlock entre threads ou processos",
                "recommendation": "Revise a lógica de sincronização e o uso de locks na aplicação."
            })
        
        if "permission" in main_message or "access denied" in main_message:
            patterns["potential_issues"].append({
                "issue": "Problema de Permissão",
                "description": "Acesso negado a um recurso",
                "recommendation": "Verifique as permissões do usuário e da aplicação para acessar o recurso."
            })
        
        return patterns
    
    def generate_fingerprint(self, message_info: Dict[str, Any]) -> str:
        """
        Gera uma impressão digital (fingerprint) para o log.
        
        Args:
            message_info: Informações extraídas da mensagem
            
        Returns:
            String representando a impressão digital do log
        """
        # Combinar informações relevantes para criar uma impressão digital
        fingerprint_data = []
        
        # Adicionar exceções
        for exception in message_info.get("exceptions", []):
            fingerprint_data.append(f"exception:{exception}")
        
        # Adicionar componentes principais
        for component in message_info.get("components", [])[:3]:
            fingerprint_data.append(f"component:{component}")
        
        # Adicionar métodos principais
        for method in message_info.get("key_methods", [])[:2]:
            fingerprint_data.append(f"method:{method}")
        
        # Se não houver informações específicas, usar a mensagem principal
        if not fingerprint_data and message_info.get("main_message"):
            fingerprint_data.append(f"message:{message_info['main_message'][:100]}")
        
        # Gerar hash
        fingerprint_str = "|".join(sorted(fingerprint_data))
        return hashlib.md5(fingerprint_str.encode()).hexdigest()
    
    def analyze(self) -> Dict[str, Any]:
        """
        Realiza a análise completa do log.
        
        Returns:
            Dicionário com a análise completa
        """
        basic_info = self.get_basic_info()
        message_info = self.extract_message_info()
        patterns = self.identify_patterns(message_info)
        fingerprint = self.generate_fingerprint(message_info)
        
        # Determinar o tipo de evento com base no nível de log e conteúdo
        event_type = "Erro" if basic_info["log_level"] in ["Error", "Critical"] else "Informação"
        if message_info["exceptions"]:
            event_type = "Exceção"
        elif "warning" in str(message_info["main_message"]).lower():
            event_type = "Alerta"
        
        # Gerar resumo
        summary = f"{event_type} em {basic_info['category']}"
        if message_info["main_message"]:
            summary += f": {message_info['main_message'][:100]}"
            if len(message_info["main_message"]) > 100:
                summary += "..."
        
        # Determinar impacto
        impact = "Baixo"
        if basic_info["log_level"] in ["Error", "Critical"]:
            impact = "Alto"
        elif basic_info["log_level"] == "Warning":
            impact = "Médio"
        
        # Gerar recomendações gerais
        recommendations = []
        
        # Adicionar recomendações específicas de exceções
        for exception_info in patterns["exception_info"]:
            recommendations.append(exception_info["recommendation"])
        
        # Adicionar recomendações de problemas potenciais
        for issue in patterns["potential_issues"]:
            recommendations.append(issue["recommendation"])
        
        # Se não houver recomendações específicas, adicionar recomendações gerais
        if not recommendations:
            if event_type == "Erro" or event_type == "Exceção":
                recommendations.append("Verifique os logs relacionados usando o Trace ID para entender o contexto completo.")
                recommendations.append("Considere revisar o código nos arquivos mencionados no stack trace.")
            elif event_type == "Alerta":
                recommendations.append("Monitore o sistema para verificar se o alerta persiste ou se torna um erro.")
        
        return {
            "basic_info": basic_info,
            "message_info": message_info,
            "patterns": patterns,
            "event_type": event_type,
            "summary": summary,
            "impact": impact,
            "recommendations": recommendations,
            "fingerprint": fingerprint
        }
    
    def generate_report(self) -> str:
        """
        Gera um relatório explicativo sobre o log.
        
        Returns:
            String formatada com o relatório
        """
        analysis = self.analyze()
        basic = analysis["basic_info"]
        message = analysis["message_info"]
        patterns = analysis["patterns"]
        
        report = [
            "=== ANÁLISE DE LOG ===",
            f"Tipo de Evento: {analysis['event_type']}",
            f"Data/Hora: {basic['timestamp']}",
            f"Nível: {basic['log_level']} (Severidade: {basic['severity']})",
            f"Categoria: {basic['category']}",
            f"Fingerprint: {analysis['fingerprint']}",
            "",
            "--- RESUMO ---",
            analysis['summary'],
            f"Impacto Estimado: {analysis['impact']}",
            "",
            "--- DETALHES ---",
            f"Mensagem Principal: {message['main_message']}",
            "",
        ]
        
        # Adicionar informações sobre exceções
        if patterns["exception_info"]:
            report.append("Exceções Identificadas:")
            for exception_info in patterns["exception_info"]:
                report.append(f"  - {exception_info['exception']}: {exception_info['description']}")
        
        # Adicionar informações sobre componentes
        report.append("")
        report.append("Componentes Envolvidos:")
        for component_info in patterns["component_info"]:
            report.append(f"  - {component_info['component']}: {component_info['description']}")
        
        # Adicionar métodos principais
        report.extend([
            "",
            "Métodos Principais:",
        ])
        
        for method in message['key_methods']:
            report.append(f"  - {method}")
        
        # Adicionar arquivos relevantes
        if message['files']:
            report.extend([
                "",
                "Arquivos Relevantes:",
            ])
            
            for file in message['files']:
                report.append(f"  - {file}")
        
        # Adicionar problemas potenciais
        if patterns["potential_issues"]:
            report.extend([
                "",
                "Problemas Potenciais Identificados:",
            ])
            
            for issue in patterns["potential_issues"]:
                report.append(f"  - {issue['issue']}: {issue['description']}")
        
        # Adicionar recomendações
        if analysis["recommendations"]:
            report.extend([
                "",
                "Recomendações:",
            ])
            
            for i, recommendation in enumerate(analysis["recommendations"], 1):
                report.append(f"  {i}. {recommendation}")
        
        # Adicionar IDs de rastreamento
        report.extend([
            "",
            "IDs de Rastreamento:",
            f"  - Trace ID: {basic['trace_id']}",
            f"  - Span ID: {basic['span_id']}",
            f"  - Trace Flags: {basic['trace_flags']}",
            "",
            "=== FIM DA ANÁLISE ==="
        ])
        
        return "\n".join(report)


def load_json_log(file_path: str) -> Dict[str, Any]:
    """
    Carrega um arquivo JSON de log.
    
    Args:
        file_path: Caminho para o arquivo JSON
        
    Returns:
        Dicionário com os dados do log
        
    Raises:
        Exception: Se ocorrer um erro ao carregar o arquivo
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError:
        raise Exception(f"Erro ao decodificar JSON do arquivo: {file_path}")
    except Exception as e:
        raise Exception(f"Erro ao ler arquivo: {str(e)}")


def main():
    """Função principal do programa."""
    if len(sys.argv) < 2:
        print("Uso: python log_analyzer.py <arquivo_log.json>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    try:
        log_data = load_json_log(file_path)
        analyzer = LogAnalyzer(log_data)
        report = analyzer.generate_report()
        print(report)
    except Exception as e:
        print(f"Erro: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
