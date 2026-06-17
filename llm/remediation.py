"""
pipeline/llm/remediation.py
============================
Modulo de remediacao automatica de vulnerabilidades via LLM.

Suporta tres providers configurados via .env:
  - claude  : Anthropic Claude API  (ANTHROPIC_API_KEY)
  - openai  : OpenAI API            (OPENAI_API_KEY)
  - ollama  : Ollama local          (OLLAMA_HOST, default http://localhost:11434)

Configuracao no ficheiro .env:
  LLM_PROVIDER=claude          # claude | openai | ollama
  LLM_MODEL=claude-sonnet-4-6  # modelo especifico do provider
  ANTHROPIC_API_KEY=sk-ant-...
  OPENAI_API_KEY=sk-...
  OLLAMA_HOST=http://localhost:11434

Schema de output por finding:
{
    "finding_id":  str   - ID do finding original
    "provider":    str   - provider usado (claude | openai | ollama)
    "model":       str   - modelo usado
    "explanation": str   - explicacao da vulnerabilidade em linguagem simples
    "patch":       str   - codigo corrigido ou instrucao de remediacao
    "references":  list  - referencias OWASP/CWE relevantes
    "error":       str   - mensagem de erro (None se sucesso)
}
"""

from __future__ import annotations

import json
import os
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from typing import Any

from dotenv import load_dotenv

load_dotenv()


# ──────────────────────────────────────────────
# Prompt do sistema (identico para todos os providers)
# ──────────────────────────────────────────────

SYSTEM_PROMPT = """Es um especialista em seguranca de aplicacoes web.
Recebes dados de uma vulnerabilidade detetada por uma ferramenta de analise de seguranca
numa aplicacao web. Os dados incluem a linguagem/framework quando disponivel na localizacao do ficheiro.

Para cada vulnerabilidade deves responder EXCLUSIVAMENTE em formato JSON valido com esta estrutura:
{
  "explanation": "Explicacao clara da vulnerabilidade em 2-3 frases, sem jargao tecnico excessivo",
  "patch": "Codigo corrigido ou instrucao concreta de remediacao. Se for codigo, usa blocos markdown.",
  "references": ["referencia OWASP ou CWE relevante", "link ou titulo adicional se aplicavel"]
}

Regras:
- Responde SEMPRE em JSON valido, sem texto antes ou depois
- A explicacao deve ser compreensivel por um programador junior
- O patch deve ser especifico e aplicavel, nao generico
- Adapta o patch a linguagem/framework inferida a partir do ficheiro afetado (ex: .py -> Python, .ts -> TypeScript)
- As referencias devem incluir o CWE ou OWASP Top 10 relevante
- Se nao houver patch de codigo possivel (ex: configuracao), descreve os passos concretos
"""


# ──────────────────────────────────────────────
# Interface base
# ──────────────────────────────────────────────

class LLMProvider(ABC):
    """Interface comum para todos os providers LLM."""

    @abstractmethod
    def complete(self, user_message: str) -> str:
        """Envia mensagem ao LLM e retorna a resposta em texto."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Nome do provider."""

    @property
    @abstractmethod
    def model(self) -> str:
        """Modelo em uso."""


# ──────────────────────────────────────────────
# Provider: Claude (Anthropic)
# ──────────────────────────────────────────────

class ClaudeProvider(LLMProvider):
    """Provider para a API da Anthropic com prompt caching no system prompt."""

    DEFAULT_MODEL = "claude-sonnet-4-6"

    def __init__(self, api_key: str, model: str | None = None):
        try:
            import anthropic as _anthropic
            self._client = _anthropic.Anthropic(api_key=api_key)
        except ImportError:
            raise RuntimeError("Pacote 'anthropic' nao encontrado. Instala com: pip install anthropic")
        self._model = model or self.DEFAULT_MODEL

    @property
    def name(self) -> str:
        return "claude"

    @property
    def model(self) -> str:
        return self._model

    def complete(self, user_message: str) -> str:
        import anthropic
        response = self._client.messages.create(
            model=self._model,
            max_tokens=1024,
            system=[
                {
                    "type": "text",
                    "text": SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},  # prompt caching
                }
            ],
            messages=[{"role": "user", "content": user_message}],
        )
        return response.content[0].text


# ──────────────────────────────────────────────
# Provider: OpenAI
# ──────────────────────────────────────────────

class OpenAIProvider(LLMProvider):
    """Provider para a API da OpenAI (compativel com qualquer endpoint OpenAI-like)."""

    DEFAULT_MODEL = "gpt-4o-mini"

    def __init__(self, api_key: str, model: str | None = None, base_url: str | None = None):
        try:
            import openai as _openai
            self._client = _openai.OpenAI(
                api_key=api_key,
                **({"base_url": base_url} if base_url else {}),
            )
        except ImportError:
            raise RuntimeError("Pacote 'openai' nao encontrado. Instala com: pip install openai")
        self._model = model or self.DEFAULT_MODEL

    @property
    def name(self) -> str:
        return "openai"

    @property
    def model(self) -> str:
        return self._model

    def complete(self, user_message: str) -> str:
        response = self._client.chat.completions.create(
            model=self._model,
            max_tokens=1024,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
        )
        return response.choices[0].message.content


# ──────────────────────────────────────────────
# Provider: Ollama (local, gratuito)
# ──────────────────────────────────────────────

class OllamaProvider(LLMProvider):
    """Provider para modelos locais via Ollama (http://localhost:11434)."""

    DEFAULT_MODEL = "llama3"
    DEFAULT_HOST  = "http://localhost:11434"

    def __init__(self, host: str | None = None, model: str | None = None):
        self._host  = (host or self.DEFAULT_HOST).rstrip("/")
        self._model = model or self.DEFAULT_MODEL

    @property
    def name(self) -> str:
        return "ollama"

    @property
    def model(self) -> str:
        return self._model

    def complete(self, user_message: str) -> str:
        payload = json.dumps({
            "model":    self._model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_message},
            ],
            "stream": False,
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{self._host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = json.loads(resp.read())
                return data["message"]["content"]
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Nao foi possivel ligar ao Ollama em '{self._host}'. "
                "Verifica se o Ollama esta a correr (ollama serve)."
            ) from exc


# ──────────────────────────────────────────────
# Factory — escolhe o provider via .env
# ──────────────────────────────────────────────

def get_provider() -> LLMProvider:
    """
    Instancia o provider configurado em LLM_PROVIDER no ficheiro .env.
    Levanta RuntimeError se a configuracao estiver incompleta.
    """
    provider_name = os.getenv("LLM_PROVIDER", "claude").lower()
    model         = os.getenv("LLM_MODEL") or None

    if provider_name == "claude":
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY nao definida no .env")
        return ClaudeProvider(api_key=api_key, model=model)

    if provider_name == "openai":
        api_key  = os.getenv("OPENAI_API_KEY", "")
        base_url = os.getenv("OPENAI_BASE_URL") or None
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY nao definida no .env")
        return OpenAIProvider(api_key=api_key, model=model, base_url=base_url)

    if provider_name == "ollama":
        host = os.getenv("OLLAMA_HOST", OllamaProvider.DEFAULT_HOST)
        return OllamaProvider(host=host, model=model)

    raise RuntimeError(
        f"Provider '{provider_name}' desconhecido. "
        "Valores validos: claude | openai | ollama"
    )


# ──────────────────────────────────────────────
# Construtor do prompt por finding
# ──────────────────────────────────────────────

def _build_user_message(finding: dict) -> str:
    """Serializa os campos relevantes do finding para o prompt do LLM."""
    lines = [
        f"Ferramenta: {finding.get('source', 'desconhecida')}",
        f"Tipo: {finding.get('type', '')}",
        f"Severidade: {finding.get('severity', '')}",
        f"Titulo: {finding.get('title', '')}",
        f"Descricao: {finding.get('description', '')}",
    ]
    if finding.get("cwe"):
        lines.append(f"CWE: {finding['cwe']}")
    if finding.get("cve"):
        lines.append(f"CVE: {finding['cve']}")
    if finding.get("file"):
        loc = finding["file"]
        if finding.get("line"):
            loc += f":{finding['line']}"
        lines.append(f"Localizacao: {loc}")
    if finding.get("url"):
        lines.append(f"URL afetado: {finding['url']}")
        if finding.get("param"):
            lines.append(f"Parametro: {finding['param']}")
    if finding.get("package"):
        lines.append(f"Pacote: {finding['package']}")

    return "\n".join(lines)


# ──────────────────────────────────────────────
# Funcoes publicas
# ──────────────────────────────────────────────

def remediate(finding: dict, provider: LLMProvider) -> dict[str, Any]:
    """
    Envia um finding ao LLM e retorna a remediacao estruturada.

    Parametros
    ----------
    finding  : finding normalizado do parser.py
    provider : instancia de LLMProvider

    Retorna
    -------
    dict com explanation, patch, references (e error se falhou)
    """
    result: dict[str, Any] = {
        "finding_id":  finding.get("id", ""),
        "provider":    provider.name,
        "model":       provider.model,
        "explanation": None,
        "patch":       None,
        "references":  [],
        "error":       None,
    }

    try:
        user_msg  = _build_user_message(finding)
        raw_text  = provider.complete(user_msg)

        # Extrair JSON da resposta — suporta: JSON puro, ```json...```, ```...```
        json_text = raw_text.strip()
        if "```" in json_text:
            # Extrai o conteudo entre o primeiro ``` e o ultimo ```
            inner = json_text.split("```", 1)[1].rsplit("```", 1)[0]
            # Remove linguagem opcional (json, JSON, etc.)
            if inner.lstrip().startswith(("json", "JSON")):
                inner = inner.lstrip()[4:]
            json_text = inner.strip()

        parsed = json.loads(json_text)
        result["explanation"] = parsed.get("explanation", "")
        result["patch"]       = parsed.get("patch", "")
        result["references"]  = parsed.get("references", [])

    except json.JSONDecodeError:
        result["explanation"] = raw_text  # guarda resposta mesmo sem ser JSON valido
        result["error"] = "Resposta nao e JSON valido"
    except Exception as exc:
        result["error"] = str(exc)

    return result


def _load_checkpoint(path: str) -> dict[str, Any]:
    """Carrega checkpoint de remediações parciais do disco."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            print(f"[LLM] Checkpoint carregado: {len(data)} findings ja processados de '{path}'")
            return data
    except FileNotFoundError:
        return {}
    except Exception as exc:
        print(f"[LLM] Aviso: nao foi possivel ler checkpoint '{path}': {exc}")
        return {}


def _save_checkpoint(path: str, done: dict[str, Any]) -> None:
    """Persiste o progresso actual no ficheiro de checkpoint."""
    try:
        import os
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(done, fh, ensure_ascii=False, indent=2)
    except Exception as exc:
        print(f"[LLM] Aviso: nao foi possivel guardar checkpoint: {exc}")


def remediate_all(
    findings: list[dict],
    provider: LLMProvider | None = None,
    max_findings: int | None = None,
    checkpoint_path: str | None = None,
) -> list[dict[str, Any]]:
    """
    Processa uma lista de findings e retorna as remediações.

    Parametros
    ----------
    findings         : lista de findings normalizados
    provider         : provider LLM (se None, usa get_provider())
    max_findings     : limitar o numero de findings processados (util para testes)
    checkpoint_path  : ficheiro JSON para guardar progresso (resume automatico se existir)

    Retorna
    -------
    lista de dicts de remediacao
    """
    if provider is None:
        provider = get_provider()

    subset = findings[:max_findings] if max_findings else findings

    # Carregar checkpoint (progresso anterior)
    done: dict[str, Any] = {}
    if checkpoint_path:
        done = _load_checkpoint(checkpoint_path)

    to_process = [f for f in subset if f.get("id") not in done]
    skipped    = len(subset) - len(to_process)

    print(f"[LLM] Provider: {provider.name} / Modelo: {provider.model}")
    if skipped:
        print(f"[LLM] Retomando: {skipped} findings ja processados, {len(to_process)} em falta")
    else:
        print(f"[LLM] A processar {len(to_process)} findings...")

    for i, finding in enumerate(to_process, 1):
        total_pending = len(to_process)
        print(f"[LLM] ({i}/{total_pending}) {finding.get('title', '')[:60]}", end=" ... ")
        rem = remediate(finding, provider)
        if rem["error"]:
            print(f"ERRO: {rem['error']}")
        else:
            print("OK")

        done[finding["id"]] = rem

        if checkpoint_path:
            _save_checkpoint(checkpoint_path, done)

    results = [done[f["id"]] for f in subset if f.get("id") in done]

    ok    = sum(1 for r in results if not r.get("error"))
    fails = len(results) - ok
    print(f"[LLM] Concluido: {ok} OK, {fails} erros")
    return results


# ──────────────────────────────────────────────
# Funcao principal de teste
# ──────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent))

    from parsers.parser import parse_semgrep, parse_snyk, parse_zap, parse_sonarqube
    from dedup.dedup import deduplicate

    findings_raw = []
    base = Path(__file__).parent.parent / "samples"
    findings_raw += parse_sonarqube(str(base / "sonarqube_juiceshop.json"))
    findings_raw += parse_semgrep(str(base / "semgrep_juiceshop.sarif"))
    findings_raw += parse_snyk(str(base / "snyk_juiceshop.json"))
    findings_raw += parse_zap(str(base / "zap_juiceshop.json"))

    result    = deduplicate(findings_raw)
    findings  = result["findings"]

    # Testar com 3 findings de severidades diferentes
    sample = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM"):
        match = next((f for f in findings if f["severity"] == sev), None)
        if match:
            sample.append(match)

    print(f"\nTeste com {len(sample)} findings ({', '.join(f['severity'] for f in sample)})\n")

    try:
        provider = get_provider()
    except RuntimeError as e:
        print(f"[LLM] {e}")
        print("[LLM] Configura o ficheiro .env com LLM_PROVIDER e a respetiva API key.")
        sys.exit(1)

    remediations = remediate_all(sample, provider)

    print("\n-- Resultados --")
    for r in remediations:
        print(f"\n[{r['finding_id']}] via {r['provider']}/{r['model']}")
        if r["error"]:
            print(f"  ERRO: {r['error']}")
        else:
            print(f"  Explicacao : {r['explanation'][:120]}...")
            print(f"  Referencias: {r['references']}")
