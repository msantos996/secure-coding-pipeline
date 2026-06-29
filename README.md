# Security Pipeline

Pipeline Python que agrega relatórios de ferramentas de segurança (SAST, DAST, SCA),
deduplica findings e gera remediações automáticas via LLM.

**Projeto de Mestrado** — Implementação de Secure Coding no Desenvolvimento Web  
Miguel Ângelo Ferreira dos Santos — TICM 2024–25, Universidade da Maia

---

## Índice

1. [Início rápido](#início-rápido)
2. [Como funciona](#como-funciona)
3. [Instalação](#instalação)
4. [Configuração do LLM](#configuração-do-llm)
5. [Usar com a tua aplicação](#usar-com-a-tua-aplicação)
   - [Semgrep (SAST)](#semgrep-sast)
   - [Snyk (SCA)](#snyk-sca)
   - [OWASP ZAP (DAST)](#owasp-zap-dast)
   - [SonarQube / SonarCloud (SAST)](#sonarqube--sonarcloud-sast)
6. [Correr o pipeline](#correr-o-pipeline)
7. [Ler o relatório](#ler-o-relatório)
8. [Modo demo (OWASP Juice Shop)](#modo-demo-owasp-juice-shop)

---

## Início rápido

Do clone ao relatório em 5 passos. Usa **apenas o Semgrep** como exemplo (gratuito, sem conta).

```bash
# 1. Clonar e instalar
git clone https://github.com/msantos996/secure-coding-pipeline.git
cd secure-coding-pipeline
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 2. Configurar o LLM (escolhe um provider)
cp .env.example .env
# Edita o .env com a tua API key

# 3. Analisar a tua aplicação com o Semgrep
pip install semgrep
semgrep scan --config "p/owasp-top-ten" --sarif --output semgrep_report.sarif /caminho/da/tua/app

# 4. Correr o pipeline
python pipeline.py --semgrep semgrep_report.sarif --app "Nome da Tua App"

# 5. Ler o relatório
# output/report.md  ← abre no VS Code com Ctrl+Shift+V
# output/report.json ← dados completos em JSON
```

> **Sem API key?** Usa `--no-llm` para correr só o parse + dedup sem custos:
> `python pipeline.py --semgrep semgrep_report.sarif --no-llm`

> **Quer testar primeiro?** Usa o modo demo com dados do OWASP Juice Shop incluídos:
> `python pipeline.py --demo --no-llm`

---

## Como funciona

```
As tuas ferramentas de segurança
  SonarQube · Semgrep · Snyk · OWASP ZAP
           |
           v  (exportar relatórios JSON/SARIF)
    [parsers/parser.py]
    Normaliza para schema comum
           |
           v
    [dedup/dedup.py]
    Remove duplicados entre ferramentas
           |
           v
    [llm/remediation.py]
    Claude / OpenAI / Ollama
    Explicação + Patch + Referências OWASP
           |
           v
    output/report.md   (relatório legível)
    output/report.json (dados completos)
```

**Schema normalizado** — cada finding tem:

| Campo | Descrição |
|---|---|
| `severity` | CRITICAL / HIGH / MEDIUM / LOW / INFO |
| `type` | SAST / DAST / SCA |
| `source` | SonarQube / Semgrep / Snyk / OWASP ZAP |
| `cwe` | ex: CWE-89 |
| `title` | título curto |
| `description` | descrição da ferramenta |
| `file` / `line` | localização no código (SAST) |
| `url` / `param` | URL e parâmetro afetado (DAST) |
| `package` | pacote vulnerável (SCA) |

---

## Instalação

**Pré-requisitos:** Python 3.10+, Git

```bash
# 1. Clonar o repositório
git clone https://github.com/msantos996/secure-coding-pipeline.git
cd secure-coding-pipeline

# 2. Criar ambiente virtual
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux / macOS
source .venv/bin/activate

# 3. Instalar dependências
pip install -r requirements.txt
```

---

## Configuração do LLM

Copia o ficheiro de exemplo e preenche o provider que queres usar:

```bash
cp .env.example .env
```

Abre o `.env` e configura:

```env
# Escolhe o provider: claude | openai | ollama
LLM_PROVIDER=claude

# Modelo (opcional — usa o default se omitido)
LLM_MODEL=claude-sonnet-4-6

# Preenche a key do provider escolhido:
ANTHROPIC_API_KEY=sk-ant-...   # https://console.anthropic.com/settings/keys
OPENAI_API_KEY=sk-...          # https://platform.openai.com/api-keys
# Ollama não precisa de key — ver instrução abaixo
```

### Usar Ollama (gratuito, local)

O Ollama corre modelos LLM localmente, sem custos e sem enviar dados para a cloud.

```bash
# 1. Instalar: https://ollama.com/download
# 2. Arrancar o servidor
ollama serve

# 3. Descarregar um modelo
ollama pull llama3        # recomendado (~4GB)
# ou: mistral, phi3, gemma2, codellama

# 4. Configurar no .env
# LLM_PROVIDER=ollama
# LLM_MODEL=llama3
```

---

## Usar com a tua aplicação

Corre uma ou mais ferramentas contra a tua aplicação e guarda os relatórios.
Não precisas de usar todas — o pipeline aceita qualquer combinação.

### Semgrep (SAST)

Analisa o código fonte em busca de vulnerabilidades. Gratuito e sem conta.

```bash
# Instalar
pip install semgrep

# Correr com regras OWASP Top 10 (recomendado)
semgrep scan \
  --config "p/owasp-top-ten" \
  --sarif \
  --output semgrep_report.sarif \
  /caminho/para/o/teu/projeto

# Alternativa: regras específicas de linguagem
semgrep scan --config "p/javascript" --sarif --output semgrep_report.sarif .
semgrep scan --config "p/python"     --sarif --output semgrep_report.sarif .
```

> **Nota Windows:** usa `set PYTHONUTF8=1 &&` antes do comando para evitar erros de encoding.

### Snyk (SCA)

Analisa as dependências em busca de vulnerabilidades conhecidas (CVEs).

```bash
# Instalar
npm install -g snyk

# Autenticar (conta gratuita em snyk.io)
snyk auth

# Correr na pasta do teu projeto (onde está o package.json, requirements.txt, etc.)
cd /caminho/para/o/teu/projeto
snyk test --json > snyk_report.json
```

Funciona com Node.js, Python, Java, .NET, Ruby, e outros.

### OWASP ZAP (DAST)

Testa a aplicação em execução com ataques automatizados. Requer a aplicação a correr.

**Pré-requisito:** [Instalar ZAP](https://www.zaproxy.org/download/) e Java 11+.

```bash
# Windows (ajusta o caminho do zap jar)
java -jar "C:\Program Files\ZAP\Zed Attack Proxy\zap-2.17.0.jar" \
  -cmd \
  -quickurl http://localhost:PORTA_DA_TUA_APP \
  -quickprogress \
  -quickout zap_report.json

# Linux / macOS
java -jar /opt/zaproxy/zap.jar \
  -cmd \
  -quickurl http://localhost:PORTA_DA_TUA_APP \
  -quickprogress \
  -quickout zap_report.json
```

### SonarQube / SonarCloud (SAST)

Análise estática profunda. Usa o [SonarCloud](https://sonarcloud.io) (gratuito para projetos open source)
ou um servidor SonarQube local.

```bash
# Instalar o scanner
npm install -g @sonar/scan

# Correr (substitui token e project key pelos teus)
sonar \
  -Dsonar.token=SEU_TOKEN \
  -Dsonar.projectKey=SEU_PROJECT_KEY \
  -Dsonar.organization=SEU_ORG \
  -Dsonar.host.url=https://sonarcloud.io \
  -Dsonar.sources=src \
  -Dsonar.exclusions="node_modules/**,**/*.spec.ts"
```

Depois de analisar, exporta os resultados via API:

```bash
curl -u SEU_TOKEN: \
  "https://sonarcloud.io/api/issues/search?componentKeys=SEU_PROJECT_KEY&ps=500" \
  > sonarqube_report.json
```

---

## Correr o pipeline

```bash
# Com os teus próprios relatórios (fornece os que tens)
python pipeline.py \
  --semgrep   semgrep_report.sarif \
  --snyk      snyk_report.json \
  --zap       zap_report.json \
  --sonarqube sonarqube_report.json

# Só alguns (podes omitir as ferramentas que não usaste)
python pipeline.py --semgrep semgrep_report.sarif --snyk snyk_report.json

# Sem LLM (só parse + dedup, sem custos de API)
python pipeline.py --semgrep scan.sarif --no-llm

# Só findings críticos e altos
python pipeline.py --semgrep scan.sarif --severity HIGH

# Limitar chamadas ao LLM (útil para testar)
python pipeline.py --semgrep scan.sarif --max 10

# Diretório de output personalizado
python pipeline.py --semgrep scan.sarif --output resultados/
```

---

## Ler o relatório

O relatório é gerado em `output/report.md` e `output/report.json`.

**Abrir o Markdown no VS Code:**
- **Ctrl+Shift+V** — preview formatado lado a lado

**Estrutura do relatório:**
```
# Relatório de Segurança
## Métricas          ← findings brutos vs únicos, por severidade e ferramenta
## Findings
### CRITICAL (N)
  #### nome da vulnerabilidade
  fonte · tipo · CWE · localização
  > descrição original da ferramenta
  Explicação LLM ...
  Remediação LLM ...
  Referências: CWE-XX, OWASP Top 10 ...
### HIGH (N)
  ...
```

---

## Modo demo (OWASP Juice Shop)

O repositório inclui relatórios reais do [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)
(aplicação web intencionalmente vulnerável) para demonstração imediata.

```bash
# Correr o pipeline com dados de demonstração
python pipeline.py --demo

# Ver apenas o parse + dedup sem LLM
python pipeline.py --demo --no-llm
```

**Resultados do Juice Shop incluídos:**

| Ferramenta | Ficheiro | Findings |
|---|---|---|
| SonarQube | `samples/sonarqube_juiceshop.json` | 222 |
| Semgrep | `samples/semgrep_juiceshop.sarif` | 22 |
| Snyk | `samples/snyk_juiceshop.json` | 117 |
| OWASP ZAP | `samples/zap_juiceshop.json` | 23 |
| **Total** | | **384 brutos → 338 únicos** |

Para recriar o ambiente de teste com o Juice Shop a correr localmente:

```bash
# Windows — setup (só na primeira vez)
setup_juiceshop.bat

# Windows — arrancar / parar
start_juiceshop.bat
stop_services.bat

# Linux / macOS — arrancar / parar
chmod +x start_juiceshop.sh stop_services.sh
./start_juiceshop.sh
./stop_services.sh
# Disponível em http://localhost:3000
```
