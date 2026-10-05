"""
ai_handoff.py — Context builder + markdown formatter for the AI team loop.

Supports N roles (currently 7). Handles plans + summaries.
"""
import re
from datetime import datetime


def _clean_text(text):
    """Strip ANSI codes, normalize newlines."""
    if not text:
        return ""
    text = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", str(text))
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return text.strip()


def _format_stage_compact(role, stage):
    """Compact one-line description of a stage."""
    if not stage:
        return f"  [{role}] (missing)"
    model = stage.get("model", "?")
    elapsed = stage.get("elapsed", 0)
    if stage.get("error"):
        return f"  [{role}] {model} ({elapsed:.1f}s) — ERROR: {_clean_text(stage['error'])[:100]}"
    out = stage.get("output") or {}
    if isinstance(out, dict):
        phases = out.get("next_phases", [])
        conf = out.get("confidence", "?")
        return f"  [{role}] {model} ({elapsed:.1f}s, conf={conf}): {phases}"
    return f"  [{role}] {model} ({elapsed:.1f}s): {str(out)[:200]}"


def build_handoff_package(target, waf, phase_name, phase_summary,
                          previous_rounds, current_model, model_role,
                          keep_full_rounds=2, state_summary=None):
    """
    Build the handoff context for the next model.

    previous_rounds: list of {round_num, summary, stages: {role: stage, ...}}
    Last `keep_full_rounds` rounds shown in full; older shown as summary only.
    """
    lines = []
    lines.append("=" * 60)
    lines.append("HANDOFF CONTEXT")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Target: {target}")
    lines.append(f"WAF: {waf}")
    lines.append(f"Phase: {phase_name}")
    lines.append(f"Current role: {model_role} ({current_model})")
    lines.append("")
    lines.append("Phase result summary:")
    lines.append(_clean_text(phase_summary))
    lines.append("")

    if previous_rounds:
        n = len(previous_rounds)
        full_start = max(0, n - keep_full_rounds)

        lines.append("-" * 60)
        lines.append(f"PREVIOUS ROUNDS (full: last {keep_full_rounds}, older: summary only)")
        lines.append("-" * 60)

        # Older rounds → summary only
        for r in previous_rounds[:full_start]:
            lines.append("")
            lines.append(f"### Round {r.get('round_num', '?')} (summary)")
            summary = r.get("summary") or "(no summary)"
            lines.append(_clean_text(summary)[:500])

        # Last N rounds → full
        for r in previous_rounds[full_start:]:
            lines.append("")
            lines.append(f"### Round {r.get('round_num', '?')} (full)")
            stages = r.get("stages", {})
            for role_name, stage in stages.items():
                lines.append(_format_stage_compact(role_name, stage))
        lines.append("")

    if state_summary:
        lines.append("-" * 60)
        lines.append("CURRENT SCAN STATE (what exists on disk)")
        lines.append("-" * 60)
        lines.append(_clean_text(state_summary))
        lines.append("")

    lines.append("-" * 60)
    lines.append("YOUR TASK")
    lines.append("-" * 60)
    if model_role == "Planner":
        lines.append("You are the PLANNER. Produce the initial best plan.")
    elif model_role == "Analyst":
        lines.append("You are the ANALYST. Read the Planner's output and improve it.")
    elif model_role == "Critic":
        lines.append("You are the CRITIC. Read prior stages, critique them, produce the refined plan.")
    elif model_role == "Coder":
        lines.append("You are the CODER. Review the plan. If phases need exact commands, provide them in reasoning.")
    elif model_role == "Vision":
        lines.append("You are the VISION role. If response bodies were captured, analyze them. Otherwise refine the plan.")
    elif model_role == "Refiner":
        lines.append("You are the REFINER. Fill gaps, sharpen the plan, remove redundant phases.")
    elif model_role == "Summarizer":
        lines.append("You are the SUMMARIZER. Produce a concise summary of the round for the next iteration.")
    else:
        lines.append(f"You are {model_role}. Contribute your best analysis.")
    lines.append("")
    return "\n".join(lines)


def format_round_markdown(target, waf, phase_name, round_num, stages, summary=None):
    """Format one round as clean markdown with all roles."""
    lines = []
    lines.append(f"# AI Team Planning — Round {round_num}")
    lines.append("")
    lines.append(f"**Target:** `{target}`  ")
    lines.append(f"**WAF:** `{waf}`  ")
    lines.append(f"**Phase:** `{phase_name}`  ")
    lines.append(f"**Timestamp:** {datetime.now().isoformat(timespec='seconds')}")
    lines.append("")
    lines.append("---")
    lines.append("")

    for role_name, stage in stages.items():
        model = stage.get("model", "?")
        elapsed = stage.get("elapsed", 0)
        lines.append(f"## {role_name} — `{model}`")
        lines.append("")
        lines.append(f"- **Elapsed:** {elapsed:.1f}s")
        if stage.get("error"):
            lines.append(f"- **Error:** {_clean_text(stage['error'])[:200]}")
            lines.append("")
            lines.append("---")
            lines.append("")
            continue

        out = stage.get("output")
        if isinstance(out, dict):
            if out.get("confidence"):
                lines.append(f"- **Confidence:** {out['confidence']}")
            lines.append("")
            if out.get("next_phases"):
                lines.append("### Next Phases")
                lines.append("")
                for p in out["next_phases"]:
                    lines.append(f"- `{p}`")
                lines.append("")
            if out.get("reasoning"):
                lines.append("### Reasoning")
                lines.append("")
                lines.append(_clean_text(out["reasoning"]))
                lines.append("")
            if out.get("custom_phases_added"):
                lines.append("### Custom Phases Added")
                lines.append("")
                for cp in out["custom_phases_added"]:
                    lines.append(f"- **`{cp.get('name', '?')}`**")
                    if cp.get("reason"):
                        lines.append(f"  - Reason: {_clean_text(cp['reason'])}")
                    if cp.get("target_subs"):
                        lines.append(f"  - Targets: {', '.join(cp['target_subs'])}")
                lines.append("")
        elif isinstance(out, str):
            lines.append(_clean_text(out))
            lines.append("")

        lines.append("---")
        lines.append("")

    if summary:
        lines.append("## Round Summary")
        lines.append("")
        lines.append(_clean_text(summary))
        lines.append("")

    return "\n".join(lines)
