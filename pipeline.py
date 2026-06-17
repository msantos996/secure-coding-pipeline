"""
pipeline.py
===========
Ponto de entrada principal do pipeline de seguranca.

Analisa os relatorios exportados pelas ferramentas de seguranca,
deduplica os findings e gera remediações automaticas via LLM.

Uso basico (com os teus proprios relatorios):
  python pipeline.py --semgrep scan.sarif --snyk snyk.json --zap zap.json

Modo demo (usa dados do OWASP Juice Shop incluidos no repositorio):
  python pipeline.py --demo

Opcoes adicionais:
  --sonarqube FILE   relatorio SonarQube JSON (/api/issues/search)
  --semgrep   FILE   relatorio Semgrep SARIF  (semgrep --sarif)
  --snyk      FILE   relatorio Snyk JSON      (snyk test --json)
  --zap       FILE   relatorio ZAP JSON       (ZAP > Report > JSON)
  --max       N      limitar N findings enviados ao LLM (teste rapido)
  --no-llm           saltar fase LLM (so parse + dedup)
  --severity  LEVEL  filtrar por severidade minima (CRITICAL|HIGH|MEDIUM|LOW|INFO)
  --output    DIR    diretorio de output (default: output/)
  --demo             usar dados de demonstracao do OWASP Juice Shop
"""

import argparse
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, str(Path(__file__).parent))

from parsers.parser import parse_sonarqube, parse_semgrep, parse_snyk, parse_zap
from dedup.dedup import deduplicate
from llm.remediation import get_provider, remediate_all
from output.report import save_markdown, save_json


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

DEMO_SAMPLES = {
    "sonarqube": "samples/sonarqube_juiceshop.json",
    "semgrep":   "samples/semgrep_juiceshop.sarif",
    "snyk":      "samples/snyk_juiceshop.json",
    "zap":       "samples/zap_juiceshop.json",
}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Pipeline de seguranca — analisa qualquer aplicacao web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # Analisar a tua aplicacao (fornece os relatorios das ferramentas que usaste)
  python pipeline.py --semgrep resultados/semgrep.sarif --snyk resultados/snyk.json

  # Modo demo com dados do OWASP Juice Shop incluidos no repositorio
  python pipeline.py --demo

  # Sem LLM (so parse + dedup, sem custos de API)
  python pipeline.py --demo --no-llm

  # So findings criticos e altos, limitado a 10 chamadas ao LLM
  python pipeline.py --semgrep scan.sarif --severity HIGH --max 10
        """,
    )

    p.add_argument("--sonarqube", metavar="FILE", help="Relatorio SonarQube JSON")
    p.add_argument("--semgrep",   metavar="FILE", help="Relatorio Semgrep SARIF")
    p.add_argument("--snyk",      metavar="FILE", help="Relatorio Snyk JSON")
    p.add_argument("--zap",       metavar="FILE", help="Relatorio OWASP ZAP JSON")
    p.add_argument("--demo",      action="store_true", help="Usar dados demo do OWASP Juice Shop")
    p.add_argument("--max",       type=int,  metavar="N",     help="Limitar N findings enviados ao LLM")
    p.add_argument("--no-llm",    action="store_true",        help="Saltar fase LLM")
    p.add_argument("--severity",  metavar="LEVEL",            help="Severidade minima: CRITICAL|HIGH|MEDIUM|LOW|INFO")
    p.add_argument("--output",    metavar="DIR", default="output", help="Diretorio de output (default: output/)")
    return p.parse_args()


def _resolve_scans(args: argparse.Namespace) -> dict[str, str | None]:
    """Resolve os caminhos dos ficheiros de scan a usar."""
    if args.demo:
        print("[Pipeline] Modo demo: a usar dados do OWASP Juice Shop")
        return DEMO_SAMPLES

    scans = {
        "sonarqube": args.sonarqube,
        "semgrep":   args.semgrep,
        "snyk":      args.snyk,
        "zap":       args.zap,
    }

    provided = {k: v for k, v in scans.items() if v}
    if not provided:
        print("Erro: nenhum relatorio fornecido.")
        print()
        print("Fornece pelo menos um relatorio de scan:")
        print("  python pipeline.py --semgrep scan.sarif")
        print("  python pipeline.py --snyk snyk.json --zap zap.json")
        print()
        print("Ou usa o modo demo para experimentar com dados do OWASP Juice Shop:")
        print("  python pipeline.py --demo")
        sys.exit(1)

    # Validar que os ficheiros existem
    for tool, path in provided.items():
        if not Path(path).exists():
            print(f"Erro: ficheiro '{path}' nao encontrado (--{tool})")
            sys.exit(1)

    return scans


PARSERS = {
    "sonarqube": parse_sonarqube,
    "semgrep":   parse_semgrep,
    "snyk":      parse_snyk,
    "zap":       parse_zap,
}


def main() -> None:
    args   = parse_args()
    scans  = _resolve_scans(args)
    output = Path(args.output)
    output.mkdir(exist_ok=True)

    t_start = time.time()

    # ── Fase 1: Parsing ────────────────────────
    print("\n=== FASE 1: PARSING ===")
    t0 = time.time()
    findings_raw = []
    for tool, path in scans.items():
        if path:
            findings_raw += PARSERS[tool](path)
    t_parse = time.time() - t0

    if not findings_raw:
        print("Nenhum finding encontrado nos ficheiros fornecidos.")
        sys.exit(0)

    # ── Fase 2: Deduplicacao ───────────────────
    print("\n=== FASE 2: DEDUPLICACAO ===")
    t0 = time.time()
    result   = deduplicate(findings_raw)
    findings = result["findings"]
    metrics  = result["metrics"]
    t_dedup  = time.time() - t0

    if args.severity:
        sev = args.severity.upper()
        if sev not in SEVERITY_ORDER:
            print(f"Severidade invalida: {sev}. Valores: {', '.join(SEVERITY_ORDER)}")
            sys.exit(1)
        sev_idx  = SEVERITY_ORDER.index(sev)
        findings = [f for f in findings
                    if f["severity"] in SEVERITY_ORDER
                    and SEVERITY_ORDER.index(f["severity"]) <= sev_idx]
        print(f"[Pipeline] Filtro >= {sev}: {len(findings)} findings")

    # ── Fase 3: LLM ───────────────────────────
    remediations: list[dict] = []
    t_llm = 0.0

    if args.no_llm:
        print("\n=== FASE 3: LLM (saltada) ===")
    else:
        print("\n=== FASE 3: REMEDIACAO LLM ===")
        t0 = time.time()
        checkpoint = str(output / "llm_checkpoint.json")
        try:
            provider = get_provider()
            remediations = remediate_all(findings, provider, max_findings=args.max, checkpoint_path=checkpoint)
        except RuntimeError as e:
            print(f"[LLM] AVISO: {e}")
            print("[LLM] A gerar relatorio sem remediações LLM.")
            print("[LLM] Configura o ficheiro .env para ativar esta fase.")
        t_llm = time.time() - t0

    t_total = time.time() - t_start

    # ── Adicionar metricas de tempo ────────────
    n_llm = len([r for r in remediations if not r.get("error")])
    metrics["timing"] = {
        "t_parse_s":          round(t_parse, 2),
        "t_dedup_s":          round(t_dedup, 2),
        "t_llm_s":            round(t_llm, 2),
        "t_total_s":          round(t_total, 2),
        "t_llm_per_finding_s": round(t_llm / n_llm, 2) if n_llm else None,
    }

    # ── Fase 4: Relatorio ──────────────────────
    print("\n=== FASE 4: RELATORIO ===")
    save_markdown(findings, remediations, metrics, str(output / "report.md"))
    save_json(findings, remediations, metrics, str(output / "report.json"))

    ok = n_llm
    t = metrics["timing"]
    print(f"\n=== CONCLUIDO ===")
    print(f"  Findings unicos  : {metrics['unique_count']}")
    print(f"  Remediações LLM  : {ok}")
    print(f"  Relatorio        : {output}/report.md")
    print(f"\n=== TEMPOS (dissertacao) ===")
    print(f"  Parse            : {t['t_parse_s']}s")
    print(f"  Dedup            : {t['t_dedup_s']}s")
    print(f"  LLM total        : {t['t_llm_s']}s")
    if t["t_llm_per_finding_s"] is not None:
        print(f"  LLM por finding  : {t['t_llm_per_finding_s']}s")
    print(f"  Total pipeline   : {t['t_total_s']}s")


if __name__ == "__main__":
    main()
