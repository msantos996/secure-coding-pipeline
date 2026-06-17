"""
pipeline/output/report.py
=========================
Gera relatorios de seguranca em Markdown e JSON a partir dos
findings unificados e das remediações do LLM.
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}


def _severity_icon(sev: str) -> str:
    return SEVERITY_EMOJI.get(sev, "⚪")


def save_json(
    findings: list[dict],
    remediations: list[dict],
    metrics: dict,
    output_path: str,
) -> None:
    """Guarda o relatorio completo em JSON."""
    rem_by_id = {r["finding_id"]: r for r in remediations}

    report = {
        "generated_at": datetime.now().isoformat(),
        "metrics":      metrics,
        "findings": [
            {**f, "remediation": rem_by_id.get(f["id"])}
            for f in findings
        ],
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, ensure_ascii=False, indent=2)

    print(f"[Report] JSON guardado em '{output_path}'")


def save_markdown(
    findings: list[dict],
    remediations: list[dict],
    metrics: dict,
    output_path: str,
) -> None:
    """Gera relatorio legivel em Markdown."""
    rem_by_id = {r["finding_id"]: r for r in remediations}
    lines: list[str] = []

    # ── Cabecalho ──────────────────────────────
    lines += [
        "# Relatorio de Seguranca — OWASP Juice Shop",
        "",
        f"**Data:** {datetime.now().strftime('%Y-%m-%d %H:%M')}  ",
        f"**Ferramentas:** SonarQube · Semgrep · Snyk · OWASP ZAP  ",
    ]
    if remediations:
        provider = remediations[0].get("provider", "")
        model    = remediations[0].get("model", "")
        lines.append(f"**LLM:** {provider} / {model}  ")
    lines.append("")

    # ── Metricas ───────────────────────────────
    lines += [
        "## Metricas",
        "",
        "| Metrica | Valor |",
        "|---|---|",
        f"| Findings brutos | {metrics.get('raw_count', 0)} |",
        f"| Findings unicos | {metrics.get('unique_count', 0)} |",
        f"| Duplicados removidos | {metrics.get('duplicates_removed', 0)} ({metrics.get('duplicate_rate', 0)}%) |",
        "",
        "**Por severidade:**",
        "",
        "| Severidade | Findings |",
        "|---|---|",
    ]
    for sev in SEVERITY_ORDER:
        count = metrics.get("by_severity", {}).get(sev, 0)
        if count:
            lines.append(f"| {_severity_icon(sev)} {sev} | {count} |")

    lines += [
        "",
        "**Por ferramenta:**",
        "",
        "| Ferramenta | Tipo | Findings |",
        "|---|---|---|",
    ]
    by_source = metrics.get("by_source", {})
    by_type   = metrics.get("by_type", {})
    tool_type = {"SonarQube": "SAST", "Semgrep": "SAST", "Snyk": "SCA", "OWASP ZAP": "DAST"}
    for src, count in sorted(by_source.items(), key=lambda x: -x[1]):
        lines.append(f"| {src} | {tool_type.get(src, '')} | {count} |")
    lines.append("")

    timing = metrics.get("timing")
    if timing:
        lines += [
            "**Tempos de execucao:**",
            "",
            "| Fase | Tempo (s) |",
            "|---|---|",
            f"| Parsing | {timing.get('t_parse_s', '-')} |",
            f"| Deduplicacao | {timing.get('t_dedup_s', '-')} |",
            f"| LLM (total) | {timing.get('t_llm_s', '-')} |",
        ]
        per = timing.get("t_llm_per_finding_s")
        if per is not None:
            lines.append(f"| LLM (por finding) | {per} |")
        lines += [
            f"| Total pipeline | {timing.get('t_total_s', '-')} |",
            "",
        ]

    # ── Findings por severidade ────────────────
    lines.append("---")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    findings_sorted = sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.index(f["severity"]) if f["severity"] in SEVERITY_ORDER else 99)
    )

    current_sev = None
    for f in findings_sorted:
        sev = f["severity"]

        if sev != current_sev:
            current_sev = sev
            count = sum(1 for x in findings if x["severity"] == sev)
            lines += [
                f"### {_severity_icon(sev)} {sev} ({count})",
                "",
            ]

        # Cabecalho do finding
        title   = f.get("title", f.get("id", ""))
        source  = f.get("source", "")
        ftype   = f.get("type", "")
        cwe     = f.get("cwe") or ""
        cve     = f.get("cve") or ""
        loc     = f.get("file") or f.get("url") or f.get("package") or ""
        line    = f.get("line")
        if loc and line:
            loc = f"{loc}:{line}"

        meta_parts = [f"**{source}**", ftype]
        if cwe:
            meta_parts.append(cwe)
        if cve:
            meta_parts.append(cve)
        if loc:
            meta_parts.append(f"`{loc}`")

        lines += [
            f"#### {title}",
            "",
            " · ".join(meta_parts),
            "",
        ]

        # Descricao original
        desc = f.get("description", "").strip()
        if desc:
            lines += [f"> {desc[:300]}{'...' if len(desc) > 300 else ''}", ""]

        # Remediacao do LLM
        rem = rem_by_id.get(f["id"])
        if rem and not rem.get("error"):
            explanation = rem.get("explanation", "").strip()
            patch       = rem.get("patch", "").strip()
            refs        = rem.get("references", [])

            if explanation:
                lines += ["**Explicacao:**", "", explanation, ""]
            if patch:
                lines += ["**Remediacao:**", "", patch, ""]
            if refs:
                lines += ["**Referencias:**", ""]
                for ref in refs:
                    lines.append(f"- {ref}")
                lines.append("")
        elif rem and rem.get("error"):
            lines += [f"*LLM: {rem['error']}*", ""]

        lines.append("---")
        lines.append("")

    content = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(content)

    print(f"[Report] Markdown guardado em '{output_path}'")
