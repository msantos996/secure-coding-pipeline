"""
pipeline/parsers/parser.py
==========================
Parser unificado para outputs de ferramentas de segurança:
  - SonarQube  (JSON)
  - Snyk       (JSON)
  - OWASP ZAP  (JSON)
  - Semgrep    (SARIF / JSON)

Cada parser normaliza para o schema comum:
{
    "id":          str   – fingerprint único (hash SHA256)
    "source":      str   – nome da ferramenta
    "type":        str   – "SAST" | "DAST" | "SCA"
    "severity":    str   – "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    "cwe":         str   – ex: "CWE-89"  (None se desconhecido)
    "cve":         str   – ex: "CVE-2021-23337" (None se não aplicável)
    "title":       str   – título curto da vulnerabilidade
    "description": str   – descrição detalhada
    "file":        str   – ficheiro afetado (None para SCA/DAST)
    "line":        int   – linha no ficheiro (None se não aplicável)
    "url":         str   – URL afetado (None para SAST/SCA)
    "param":       str   – parâmetro HTTP afetado (None se não aplicável)
    "package":     str   – pacote/dependência (None para SAST/DAST)
    "raw":         dict  – objeto original intacto
}
"""

import json
import hashlib
from pathlib import Path


# ──────────────────────────────────────────────
# Mapeamentos de severidade → normalizado
# ──────────────────────────────────────────────

SEVERITY_MAP_SONAR = {
    "BLOCKER":  "CRITICAL",
    "CRITICAL": "HIGH",
    "MAJOR":    "MEDIUM",
    "MINOR":    "LOW",
    "INFO":     "INFO",
}

SEVERITY_MAP_SNYK = {
    "critical": "CRITICAL",
    "high":     "HIGH",
    "medium":   "MEDIUM",
    "low":      "LOW",
}

ZAP_RISK_MAP = {
    "3": "HIGH",
    "2": "MEDIUM",
    "1": "LOW",
    "0": "INFO",
}

SEMGREP_LEVEL_MAP = {
    "error":   "HIGH",
    "warning": "MEDIUM",
    "note":    "LOW",
}


# ──────────────────────────────────────────────
# Utilitários
# ──────────────────────────────────────────────

def _fingerprint(*parts: str) -> str:
    """Gera um ID único baseado nos campos mais estáveis da finding."""
    combined = "|".join(str(p).strip().lower() for p in parts if p)
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


# ──────────────────────────────────────────────
# Parser: SonarQube
# ──────────────────────────────────────────────

def parse_sonarqube(path: str) -> list[dict]:
    """
    Lê o JSON exportado pelo SonarQube (endpoint /api/issues/search).
    Cada issue é normalizado para o schema comum.
    """
    data = _load_json(path)
    findings = []

    for issue in data.get("issues", []):
        component = issue.get("component", "")
        # Remove o prefixo "projeto:" que o SonarQube adiciona
        file_path = component.split(":")[-1] if ":" in component else component
        line = issue.get("line")
        rule = issue.get("rule", "")

        finding = {
            "id":          _fingerprint("sonarqube", rule, file_path, str(line)),
            "source":      "SonarQube",
            "type":        "SAST",
            "severity":    SEVERITY_MAP_SONAR.get(issue.get("severity", ""), "INFO"),
            "cwe":         None,   # SonarQube não exporta CWE diretamente neste endpoint
            "cve":         None,
            "title":       rule,
            "description": issue.get("message", ""),
            "file":        file_path,
            "line":        line,
            "url":         None,
            "param":       None,
            "package":     None,
            "raw":         issue,
        }
        findings.append(finding)

    print(f"[SonarQube] {len(findings)} findings carregados de '{path}'")
    return findings


# ──────────────────────────────────────────────
# Parser: Snyk
# ──────────────────────────────────────────────

def parse_snyk(path: str) -> list[dict]:
    """
    Lê o JSON exportado pelo Snyk (snyk test --json).
    Cada vulnerabilidade de dependência é normalizada.
    """
    data = _load_json(path)
    findings = []

    for vuln in data.get("vulnerabilities", []):
        pkg   = vuln.get("packageName", "")
        ver   = vuln.get("version", "")
        vid   = vuln.get("id", "")
        cves  = vuln.get("identifiers", {}).get("CVE", [])
        cwes  = vuln.get("identifiers", {}).get("CWE", [])

        finding = {
            "id":          _fingerprint("snyk", vid, pkg, ver),
            "source":      "Snyk",
            "type":        "SCA",
            "severity":    SEVERITY_MAP_SNYK.get(vuln.get("severity", ""), "INFO"),
            "cwe":         cwes[0] if cwes else None,
            "cve":         cves[0] if cves else None,
            "title":       vuln.get("title", ""),
            "description": vuln.get("description", ""),
            "file":        None,
            "line":        None,
            "url":         None,
            "param":       None,
            "package":     f"{pkg}@{ver}",
            "raw":         vuln,
        }
        findings.append(finding)

    print(f"[Snyk] {len(findings)} findings carregados de '{path}'")
    return findings


# ──────────────────────────────────────────────
# Parser: OWASP ZAP
# ──────────────────────────────────────────────

def parse_zap(path: str) -> list[dict]:
    """
    Lê o JSON exportado pelo OWASP ZAP (Report > JSON).
    Cada alerta pode ter múltiplas instâncias; cada instância
    é tratada como uma finding individual.
    """
    data = _load_json(path)
    findings = []

    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            cwe_id   = alert.get("cweid", "")
            cwe      = f"CWE-{cwe_id}" if cwe_id and str(cwe_id).lstrip("-").isdigit() and int(cwe_id) > 0 else None
            title    = alert.get("name", alert.get("alert", ""))
            desc     = alert.get("desc", "")
            severity = ZAP_RISK_MAP.get(str(alert.get("riskcode", "0")), "INFO")

            for instance in alert.get("instances", [{}]):
                uri   = instance.get("uri", "")
                param = instance.get("param", None)

                finding = {
                    "id":          _fingerprint("zap", cwe_id, uri, param or ""),
                    "source":      "OWASP ZAP",
                    "type":        "DAST",
                    "severity":    severity,
                    "cwe":         cwe,
                    "cve":         None,
                    "title":       title,
                    "description": desc,
                    "file":        None,
                    "line":        None,
                    "url":         uri,
                    "param":       param if param else None,
                    "package":     None,
                    "raw":         {**alert, "_instance": instance},
                }
                findings.append(finding)

    print(f"[OWASP ZAP] {len(findings)} findings carregados de '{path}'")
    return findings


# ──────────────────────────────────────────────
# Parser: Semgrep (SARIF)
# ──────────────────────────────────────────────

def _semgrep_extract_cwe(tags: list) -> str | None:
    """Extrai o primeiro CWE da lista de tags do Semgrep (ex: 'CWE-89: SQL Injection' -> 'CWE-89')."""
    import re
    for tag in tags:
        m = re.match(r"(CWE-\d+)", str(tag))
        if m:
            return m.group(1)
    return None


def parse_semgrep(path: str) -> list[dict]:
    """
    Lê o output SARIF do Semgrep (semgrep --sarif).
    Navega na estrutura runs[].results[] e cruza com runs[].tool.driver.rules[]
    para obter metadados adicionais (CWE, título, severidade).
    """
    data = _load_json(path)
    findings = []

    for run in data.get("runs", []):
        # Constrói lookup de regras pelo id
        rules_lookup = {
            rule["id"]: rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
        }

        for result in run.get("results", []):
            rule_id  = result.get("ruleId", "")
            rule_obj = rules_lookup.get(rule_id, {})
            tags     = rule_obj.get("properties", {}).get("tags", [])

            # Level: preferir o do resultado; fallback para defaultConfiguration da regra
            level = (
                result.get("level")
                or rule_obj.get("defaultConfiguration", {}).get("level")
                or "warning"
            )

            msg = result.get("message", {}).get("text", "")

            # Título: fullDescription é mais descritivo que shortDescription no Semgrep
            full_desc = rule_obj.get("fullDescription", {}).get("text", "")
            short_desc = rule_obj.get("shortDescription", {}).get("text", "")
            # shortDescription do Semgrep é frequentemente "Semgrep Finding: {rule_id}" — ignorar
            if short_desc.startswith("Semgrep Finding:"):
                short_desc = ""
            title = short_desc or (full_desc[:120] if full_desc else rule_id)

            # Localização física (pode não existir)
            locations  = result.get("locations", [])
            loc        = locations[0] if locations else {}
            phys       = loc.get("physicalLocation", {})
            art_uri    = phys.get("artifactLocation", {}).get("uri", None)
            region     = phys.get("region", {})
            start_line = region.get("startLine", None)

            # Fingerprint nativo do Semgrep se válido (não é placeholder "requires login")
            native_fp = result.get("fingerprints", {}).get("matchBasedId/v1", "")
            is_valid_fp = native_fp and native_fp not in ("requires login",)
            computed_id = (
                native_fp[:16] if is_valid_fp
                else _fingerprint("semgrep", rule_id, art_uri or "", str(start_line))
            )

            finding = {
                "id":          computed_id,
                "source":      "Semgrep",
                "type":        "SAST",
                "severity":    SEMGREP_LEVEL_MAP.get(level, "INFO"),
                "cwe":         _semgrep_extract_cwe(tags),
                "cve":         None,
                "title":       title,
                "description": msg,
                "file":        art_uri,
                "line":        start_line,
                "url":         None,
                "param":       None,
                "package":     None,
                "raw":         result,
            }
            findings.append(finding)

    print(f"[Semgrep] {len(findings)} findings carregados de '{path}'")
    return findings


# ──────────────────────────────────────────────
# Função principal de teste
# ──────────────────────────────────────────────

if __name__ == "__main__":
    base = Path(__file__).parent.parent / "samples"

    all_findings = []
    all_findings += parse_sonarqube(str(base / "sonarqube_report.json"))
    all_findings += parse_snyk(str(base / "snyk_report.json"))
    all_findings += parse_zap(str(base / "zap_report.json"))
    all_findings += parse_semgrep(str(base / "semgrep_report.sarif"))

    print(f"\nTotal de findings normalizados: {len(all_findings)}")
    print("\n── Exemplo: primeiro finding de cada ferramenta ──")
    seen = set()
    for f in all_findings:
        src = f["source"]
        if src not in seen:
            seen.add(src)
            print(f"\n[{src}]")
            for k, v in f.items():
                if k != "raw":
                    print(f"  {k:15} = {v}")
