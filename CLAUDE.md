# Pipeline de Segurança — Dissertação de Mestrado

## Contexto Académico
- **Título:** Implementação de Secure Coding no Desenvolvimento Web
- **Autor:** Miguel Ângelo Ferreira dos Santos
- **Curso:** Mestrado em Tecnologias da Informação, Comunicação e Multimédia — Informática e Segurança da Informação (TICM 2024–25)
- **Universidade:** Universidade da Maia
- **Orientadores:** Prof. Dr. Alexandre Valente Sousa / Prof. Dr. Sérgio João Silva

## Objetivo do Projeto
Pipeline Python que resolve o problema de "fadiga de ferramentas" no DevSecOps.
Agrega relatórios de múltiplas ferramentas de segurança (SAST, DAST, SCA),
desduplica findings, e usa LLMs para gerar remediações automáticas e contextualizadas.

A aplicação-alvo para testes é o **OWASP Juice Shop** (aplicação vulnerável open-source).

---

## Stack Técnica
- **Linguagem:** Python 3.10+
- **Editor:** VS Code com Claude Code extension
- **OS:** Windows (PowerShell / CMD)
- **Ambiente virtual:** `.venv` na raiz do projeto
- **Dependências:** `anthropic`, `python-dotenv`
- **Sem frameworks web** — scripts standalone
- **Formatos de input:** JSON (SonarQube, Snyk, ZAP) e SARIF (Semgrep)
- **LLM target:** Claude API via `anthropic` SDK (integração deixada para fase final)

---

## Estrutura de Ficheiros
```
pipeline/
├── CLAUDE.md                  ← este ficheiro (briefing do projeto)
├── .claudeignore              ← ficheiros ignorados pelo Claude
├── .env                       ← ANTHROPIC_API_KEY (nunca commitar)
├── .venv/                     ← ambiente virtual Python (nunca commitar)
├── parsers/
│   └── parser.py              ← ✅ FEITO — normalização de outputs
├── dedup/
│   └── dedup.py               ← 🔜 PRÓXIMO — motor de desduplicação
├── llm/
│   └── remediation.py         ← ⏳ PENDENTE — integração Claude API
├── output/                    ← relatórios gerados (ignorado pelo Claude)
└── samples/                   ← ficheiros de teste simulados (não modificar)
    ├── sonarqube_report.json
    ├── snyk_report.json
    ├── zap_report.json
    └── semgrep_report.sarif
```

---

## Schema Normalizado (output do parser)

Cada finding do `parser.py` segue este schema comum:

```python
{
    "id":          str,   # fingerprint SHA256[:16] — chave de desduplicação
    "source":      str,   # "SonarQube" | "Snyk" | "OWASP ZAP" | "Semgrep"
    "type":        str,   # "SAST" | "DAST" | "SCA"
    "severity":    str,   # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    "cwe":         str,   # ex: "CWE-89" (None se desconhecido)
    "cve":         str,   # ex: "CVE-2021-23337" (None se não aplicável)
    "title":       str,   # título curto da vulnerabilidade
    "description": str,   # descrição detalhada
    "file":        str,   # ficheiro afetado (None para SCA/DAST)
    "line":        int,   # linha no ficheiro (None se não aplicável)
    "url":         str,   # URL afetado (None para SAST/SCA)
    "param":       str,   # parâmetro HTTP afetado (None se não aplicável)
    "package":     str,   # pacote/dependência (None para SAST/DAST)
    "raw":         dict,  # objeto original intacto para contexto LLM
}
```

---

## Módulos — Estado e Detalhes

### ✅ parsers/parser.py — CONCLUÍDO

Quatro parsers independentes, cada um normaliza para o schema acima:

| Função | Ferramenta | Formato | Tipo |
|---|---|---|---|
| `parse_sonarqube(path)` | SonarQube | JSON (`/api/issues/search`) | SAST |
| `parse_snyk(path)` | Snyk | JSON (`snyk test --json`) | SCA |
| `parse_zap(path)` | OWASP ZAP | JSON (Report > JSON) | DAST |
| `parse_semgrep(path)` | Semgrep | SARIF (`semgrep --sarif`) | SAST |

**Utilitários internos:**
- `_fingerprint(*parts)` — gera SHA256[:16] para deduplicação
- `_load_json(path)` — lê qualquer JSON/SARIF do disco

**Mapeamentos de severidade normalizados:**
- SonarQube: `BLOCKER→CRITICAL`, `CRITICAL→HIGH`, `MAJOR→MEDIUM`, `MINOR→LOW`
- Snyk: `critical→CRITICAL`, `high→HIGH`, `medium→MEDIUM`, `low→LOW`
- ZAP: `riskcode "3"→HIGH`, `"2"→MEDIUM`, `"1"→LOW`, `"0"→INFO`
- Semgrep: `error→HIGH`, `warning→MEDIUM`, `note→LOW`

**Resultado dos testes com dados simulados:**
- SonarQube: 4 findings
- Snyk: 3 findings
- OWASP ZAP: 3 findings
- Semgrep: 2 findings
- **Total: 12 findings normalizados**

---

### 🔜 dedup/dedup.py — PRÓXIMO MÓDULO

**Objetivo:** receber a lista de 12 findings do parser e produzir a
"Fonte Única de Verdade" — eliminando duplicados e correlacionando
findings do mesmo tipo entre ferramentas diferentes.

**Lógica planeada:**
1. **Desduplicação exata** — agrupa findings com `id` idêntico
2. **Desduplicação cruzada** — agrupa por `cwe + file + line` semelhantes
   (o mesmo XSS detetado pelo SonarQube E pelo Semgrep = 1 finding unificado)
3. **Métricas** — calcula deteções brutas vs. líquidas (para a dissertação)

**Métricas que este módulo deve produzir:**
- `raw_count` — total de findings antes da desduplicação
- `unique_count` — total após desduplicação
- `duplicate_rate` — percentagem de duplicados eliminados
- `by_severity` — contagem por severidade normalizada
- `by_source` — contagem por ferramenta
- `by_type` — contagem SAST / DAST / SCA

---

### ⏳ llm/remediation.py — FASE FINAL

**Objetivo:** enviar cada finding unificado ao Claude API e obter:
- Explicação da vulnerabilidade em linguagem simples
- Patch de código seguro e funcional
- Referências OWASP/CWE relevantes

**Dependências:** `anthropic` SDK, `ANTHROPIC_API_KEY` no `.env`
**Nota:** integração com API deixada para fase final (verificar plano/créditos primeiro)

---

## Convenções de Código
- **Type hints** em todas as funções
- **Docstrings** em português
- **Nomes de variáveis** em inglês
- Funções focadas — máximo ~30 linhas
- Sempre tratar exceções nos parsers (try/except com mensagem clara)
- Prints de progresso no formato `[NomeFerramenta] X findings carregados de 'path'`

## O que NÃO fazer
- Nunca hardcodar API keys (usar `os.getenv()` + `python-dotenv`)
- Nunca modificar ficheiros em `samples/` — são dados de teste fixos
- Não usar bibliotecas externas desnecessárias
- Não misturar lógica de parsing com lógica de deduplicação

---

## Contexto da Dissertação — Métricas a Validar
O pipeline deve produzir evidências empíricas para estas métricas (Capítulo 6.3):

1. **Deteções Brutas vs. Líquidas** — redução de ruído após desduplicação
2. **Tempo de Remediação** — com vs. sem suporte de IA
3. **Fiabilidade da IA** — % de patches seguros e funcionais (reanálise SAST)
4. **Relação Ruído-Sinal** — redução de falsos positivos por correlação entre ferramentas

---

## Referências Relevantes do Projeto
- OWASP Top 10 (2025): https://owasp.org/www-project-top-ten/
- OWASP Juice Shop: https://owasp.org/www-project-juice-shop/
- SonarQube Docs: https://docs.sonarqube.org/
- Snyk Docs: https://docs.snyk.io/
- Formato SARIF: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
- Anthropic API: https://docs.anthropic.com/