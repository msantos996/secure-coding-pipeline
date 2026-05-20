# Pipeline de Segurança — Dissertação de Mestrado

**Implementação de Secure Coding no Desenvolvimento Web**  
Miguel Ângelo Ferreira dos Santos — TICM 2024–25, Universidade da Maia

---

## Objetivo

Pipeline Python que agrega relatórios de múltiplas ferramentas de segurança (SAST, DAST, SCA),
desduplica findings e usa LLMs para gerar remediações automáticas contextualizadas.

A aplicação-alvo é o **OWASP Juice Shop** (aplicação web intencionalmente vulnerável).

---

## Estrutura

```
project/
├── parsers/parser.py          # Normaliza outputs de SonarQube, Snyk, ZAP, Semgrep
├── dedup/dedup.py             # Motor de desduplicação (exata + cruzada)
├── llm/remediation.py         # (fase final) Integração Claude API
├── samples/                   # Relatórios reais do Juice Shop
│   ├── semgrep_juiceshop.sarif
│   ├── snyk_juiceshop.json
│   └── zap_juiceshop.json
├── setup_juiceshop.bat        # Script de setup automático do Juice Shop
└── CLAUDE.md                  # Briefing do projeto para o Claude Code
```

---

## Instalação

### 1. Clonar este repositório

```bash
git clone <url-deste-repo>
cd project
```

### 2. Criar ambiente virtual Python

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install semgrep anthropic python-dotenv
```

### 3. Configurar o Juice Shop (aplicação-alvo)

```bat
setup_juiceshop.bat
```

O script clona o Juice Shop, instala dependências, compila o frontend Angular e o servidor TypeScript.  
Requer: **Node.js 22+**, **Git**, **npm**.

### 4. Arrancar o Juice Shop

```bash
cd ..\juice-shop
npx tsx app.ts
# Disponível em http://localhost:3000
```

---

## Uso do Pipeline

```python
from parsers.parser import parse_semgrep, parse_snyk, parse_zap
from dedup.dedup import deduplicate

findings = []
findings += parse_semgrep("samples/semgrep_juiceshop.sarif")
findings += parse_snyk("samples/snyk_juiceshop.json")
findings += parse_zap("samples/zap_juiceshop.json")

result = deduplicate(findings)
print(result["metrics"])
```

---

## Ferramentas de Segurança

| Ferramenta | Tipo | Como correr |
|---|---|---|
| Semgrep | SAST | `.venv\Scripts\semgrep scan --config p/owasp-top-ten --sarif --output samples/semgrep_juiceshop.sarif ..\juice-shop` |
| Snyk | SCA | `cd ..\juice-shop && snyk test --json > ..\project\samples\snyk_juiceshop.json` |
| OWASP ZAP | DAST | Requer ZAP instalado — ver `CLAUDE.md` |

---

## Resultados (Juice Shop)

| Métrica | Valor |
|---|---|
| Findings brutos (3 ferramentas) | 162 |
| Findings únicos após dedup | 122 |
| Duplicados removidos | 40 (24.69%) |
| CRITICAL | 2 |
| HIGH | 48 |
| MEDIUM | 59 |
| LOW | 5 |
| INFO | 8 |

---

## Variáveis de Ambiente

Criar ficheiro `.env` na raiz (nunca commitar):

```
ANTHROPIC_API_KEY=sk-ant-...
```
