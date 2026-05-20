"""
pipeline/dedup/dedup.py
=======================
Motor de desduplicação de findings de segurança.

Recebe a lista normalizada produzida pelo parser.py e aplica dois níveis
de desduplicação:

1. Desduplicação exata   — agrupa findings com o mesmo campo "id" (SHA256).
2. Desduplicação cruzada — agrupa findings de ferramentas diferentes que
   partilham (cwe, file, line) não nulos, tratando-os como a mesma
   vulnerabilidade detetada por múltiplas ferramentas.

Retorna um dicionário com:
  - "findings"        : lista de findings unificados ("Fonte Única de Verdade")
  - "metrics"         : métricas de desduplicação para a dissertação
  - "duplicate_groups": lista de grupos de duplicados (para auditoria)

Schema de um finding unificado (extensão do schema do parser):
{
    ...todos os campos do schema normalizado...,
    "sources":    list[str]  – todas as ferramentas que detetaram este finding
    "duplicates": list[str]  – IDs dos findings absorvidos (exceto o canónico)
}
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any


# ──────────────────────────────────────────────
# Desduplicação exata
# ──────────────────────────────────────────────

def _dedup_exact(findings: list[dict]) -> tuple[list[dict], list[list[str]]]:
    """
    Agrupa findings com o mesmo campo 'id'.
    Retorna os findings canónicos e os grupos de duplicados exatos.
    """
    groups: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        groups[f["id"]].append(f)

    canonical: list[dict] = []
    dup_groups: list[list[str]] = []

    for fid, group in groups.items():
        leader = dict(group[0])
        # Consolida as fontes de todos os duplicados exatos
        all_sources: list[str] = list({g["source"] for g in group})
        leader["sources"] = all_sources
        leader["duplicates"] = [g["id"] for g in group[1:]]
        canonical.append(leader)

        if len(group) > 1:
            dup_groups.append([g["id"] for g in group])

    return canonical, dup_groups


# ──────────────────────────────────────────────
# Desduplicação cruzada
# ──────────────────────────────────────────────

def _cross_key(finding: dict) -> str | None:
    """
    Calcula a chave de agrupamento cruzado: 'cwe|file|line'.
    Retorna None se algum dos três campos for None (não deduplica sem contexto).
    """
    cwe  = finding.get("cwe")
    file = finding.get("file")
    line = finding.get("line")
    if cwe is None or file is None or line is None:
        return None
    return f"{str(cwe).lower()}|{str(file).lower()}|{str(line)}"


def _dedup_cross(findings: list[dict]) -> tuple[list[dict], list[list[str]]]:
    """
    Agrupa findings de ferramentas diferentes que partilham (cwe, file, line).
    O finding canónico é o de maior severidade; os restantes são absorvidos.
    """
    SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    groups: dict[str, list[dict]] = defaultdict(list)
    no_key: list[dict] = []

    for f in findings:
        key = _cross_key(f)
        if key is None:
            no_key.append(f)
        else:
            groups[key].append(f)

    canonical: list[dict] = []
    dup_groups: list[list[str]] = []

    for key, group in groups.items():
        # Elege o finding com maior severidade como canónico
        group_sorted = sorted(group, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))
        leader = dict(group_sorted[0])

        all_sources: list[str] = list({g["source"] for g in group})
        absorbed_ids: list[str] = [g["id"] for g in group_sorted[1:]]

        # Preserva fontes já consolidadas na fase exata
        existing_sources: list[str] = leader.get("sources", [leader["source"]])
        for g in group_sorted[1:]:
            existing_sources.extend(g.get("sources", [g["source"]]))
        leader["sources"] = list(set(existing_sources))

        existing_dups: list[str] = leader.get("duplicates", [])
        leader["duplicates"] = list(set(existing_dups + absorbed_ids))

        canonical.append(leader)

        if len(group) > 1:
            dup_groups.append([g["id"] for g in group])

    canonical.extend(no_key)
    return canonical, dup_groups


# ──────────────────────────────────────────────
# Cálculo de métricas
# ──────────────────────────────────────────────

def _compute_metrics(
    raw: list[dict],
    unified: list[dict],
    exact_groups: list[list[str]],
    cross_groups: list[list[str]],
) -> dict[str, Any]:
    """
    Calcula as métricas de desduplicação para a dissertação.
    """
    raw_count    = len(raw)
    unique_count = len(unified)
    removed      = raw_count - unique_count
    dup_rate     = round(removed / raw_count * 100, 2) if raw_count else 0.0

    by_severity: dict[str, int] = defaultdict(int)
    by_source:   dict[str, int] = defaultdict(int)
    by_type:     dict[str, int] = defaultdict(int)

    for f in unified:
        by_severity[f["severity"]] += 1
        by_type[f["type"]] += 1
        for src in f.get("sources", [f["source"]]):
            by_source[src] += 1

    return {
        "raw_count":      raw_count,
        "unique_count":   unique_count,
        "duplicates_removed": removed,
        "duplicate_rate": dup_rate,
        "exact_groups":   len(exact_groups),
        "cross_groups":   len(cross_groups),
        "by_severity":    dict(by_severity),
        "by_source":      dict(by_source),
        "by_type":        dict(by_type),
    }


# ──────────────────────────────────────────────
# Ponto de entrada público
# ──────────────────────────────────────────────

def deduplicate(findings: list[dict]) -> dict[str, Any]:
    """
    Recebe a lista de findings normalizados pelo parser.py e retorna um
    dicionário com os findings unificados e as métricas de desduplicação.

    Parâmetros
    ----------
    findings : list[dict]
        Lista de findings no schema normalizado do parser.py.

    Retorna
    -------
    dict com chaves:
        "findings"         – lista de findings unificados
        "metrics"          – métricas de desduplicação
        "duplicate_groups" – lista de grupos de IDs duplicados (auditoria)
    """
    try:
        if not findings:
            return {
                "findings": [],
                "metrics": _compute_metrics([], [], [], []),
                "duplicate_groups": [],
            }

        # Fase 1 — desduplicação exata por "id"
        after_exact, exact_groups = _dedup_exact(findings)
        print(f"[Dedup] Fase 1 (exata):   {len(findings)} -> {len(after_exact)} findings")

        # Fase 2 — desduplicação cruzada por "cwe + file + line"
        after_cross, cross_groups = _dedup_cross(after_exact)
        print(f"[Dedup] Fase 2 (cruzada): {len(after_exact)} -> {len(after_cross)} findings")

        metrics = _compute_metrics(findings, after_cross, exact_groups, cross_groups)
        all_dup_groups = exact_groups + cross_groups

        print(
            f"[Dedup] Total: {metrics['raw_count']} brutos -> "
            f"{metrics['unique_count']} unicos "
            f"({metrics['duplicate_rate']}% duplicados removidos)"
        )

        return {
            "findings":         after_cross,
            "metrics":          metrics,
            "duplicate_groups": all_dup_groups,
        }

    except Exception as exc:
        raise RuntimeError(f"[Dedup] Erro durante desduplicação: {exc}") from exc


# ──────────────────────────────────────────────
# Função principal de teste
# ──────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    from pathlib import Path

    # Adiciona a raiz do projeto ao path para importar o parser
    sys.path.insert(0, str(Path(__file__).parent.parent))

    from parsers.parser import (
        parse_sonarqube,
        parse_snyk,
        parse_zap,
        parse_semgrep,
    )

    base = Path(__file__).parent.parent / "samples"

    all_findings: list[dict] = []
    all_findings += parse_sonarqube(str(base / "sonarqube_report.json"))
    all_findings += parse_snyk(str(base / "snyk_report.json"))
    all_findings += parse_zap(str(base / "zap_report.json"))
    all_findings += parse_semgrep(str(base / "semgrep_report.sarif"))

    print(f"\nTotal bruto: {len(all_findings)} findings\n")

    result = deduplicate(all_findings)

    print("\n-- Metricas --")
    for k, v in result["metrics"].items():
        print(f"  {k:25} = {v}")

    print(f"\n-- Findings unificados ({result['metrics']['unique_count']}) --")
    for f in result["findings"]:
        sources = ", ".join(f.get("sources", [f["source"]]))
        dups    = len(f.get("duplicates", []))
        print(
            f"  [{f['severity']:8}] {f['title'][:55]:<55} "
            f"| fontes: {sources}"
            + (f" | absorveu: {dups}" if dups else "")
        )
