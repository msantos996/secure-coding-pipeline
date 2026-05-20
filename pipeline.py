"""
pipeline.py
===========
Ponto de entrada principal do pipeline de seguranca.

Uso:
  python pipeline.py                  # processa todos os findings
  python pipeline.py --max 20         # limita a 20 findings para teste
  python pipeline.py --no-llm         # salta a fase LLM (so parse + dedup)
  python pipeline.py --severity HIGH  # filtra por severidade minima

O relatorio e guardado em output/report.md e output/report.json.
"""

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

# Adiciona o diretorio raiz ao path
sys.path.insert(0, str(Path(__file__).parent))

from parsers.parser import parse_sonarqube, parse_semgrep, parse_snyk, parse_zap
from dedup.dedup import deduplicate
from llm.remediation import get_provider, remediate_all
from output.report import save_markdown, save_json


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SAMPLES = {
    "sonarqube": "samples/sonarqube_juiceshop.json",
    "semgrep":   "samples/semgrep_juiceshop.sarif",
    "snyk":      "samples/snyk_juiceshop.json",
    "zap":       "samples/zap_juiceshop.json",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Pipeline de seguranca — OWASP Juice Shop")
    p.add_argument("--max",      type=int,  default=None, help="Limitar numero de findings enviados ao LLM")
    p.add_argument("--no-llm",   action="store_true",     help="Saltar fase LLM (so parse + dedup)")
    p.add_argument("--severity", type=str,  default=None, help="Severidade minima: CRITICAL|HIGH|MEDIUM|LOW|INFO")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    # ── Fase 1: Parsing ────────────────────────
    print("\n=== FASE 1: PARSING ===")
    findings_raw = []
    findings_raw += parse_sonarqube(SAMPLES["sonarqube"])
    findings_raw += parse_semgrep(SAMPLES["semgrep"])
    findings_raw += parse_snyk(SAMPLES["snyk"])
    findings_raw += parse_zap(SAMPLES["zap"])

    # ── Fase 2: Deduplicacao ───────────────────
    print("\n=== FASE 2: DEDUPLICACAO ===")
    result   = deduplicate(findings_raw)
    findings = result["findings"]
    metrics  = result["metrics"]

    # Filtrar por severidade minima se pedido
    if args.severity:
        sev_idx  = SEVERITY_ORDER.index(args.severity.upper()) if args.severity.upper() in SEVERITY_ORDER else 99
        findings = [f for f in findings if SEVERITY_ORDER.index(f["severity"]) <= sev_idx
                    if f["severity"] in SEVERITY_ORDER]
        print(f"[Pipeline] Filtro aplicado: >= {args.severity} -> {len(findings)} findings")

    # ── Fase 3: LLM ───────────────────────────
    remediations: list[dict] = []

    if args.no_llm:
        print("\n=== FASE 3: LLM (saltada) ===")
    else:
        print("\n=== FASE 3: REMEDIACAO LLM ===")
        try:
            provider = get_provider()
        except RuntimeError as e:
            print(f"[LLM] AVISO: {e}")
            print("[LLM] A gerar relatorio sem remediações LLM.")
            provider = None

        if provider:
            remediations = remediate_all(findings, provider, max_findings=args.max)

    # ── Fase 4: Relatorio ──────────────────────
    print("\n=== FASE 4: RELATORIO ===")
    save_markdown(findings, remediations, metrics, str(output_dir / "report.md"))
    save_json(findings, remediations, metrics, str(output_dir / "report.json"))

    print(f"\n=== CONCLUIDO ===")
    print(f"  Findings unicos : {metrics['unique_count']}")
    print(f"  Remediações LLM : {len([r for r in remediations if not r.get('error')])}")
    print(f"  Relatorio MD    : output/report.md")
    print(f"  Relatorio JSON  : output/report.json")


if __name__ == "__main__":
    main()
