from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

import yaml
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanners.ai_agent.agent import run_dry_scan, run_scan, save_results
from scanners.ai_agent.auth import load_targets
from scanners.ai_agent.llm_config import LLMRouter, check_connectivity


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config/scanner_config.yaml")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--target", help="Run only specific target ID")
    parser.add_argument("--model", help="Run only specific model")
    args = parser.parse_args()

    proj_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env_path = os.path.join(proj_root, "config", "targets.env")
    load_dotenv(env_path)

    conn = check_connectivity()
    available = conn.get("available_models", [])
    if not available:
        print("No models available. Check API keys and connectivity.")
        sys.exit(1)
    print("Available models:", available)

    config_path = args.config
    if not os.path.isabs(config_path):
        config_path = os.path.join(proj_root, config_path)
    config_dir = os.path.dirname(config_path)

    targets = load_targets(config_path)
    if not targets:
        print("No targets loaded from config.")
        sys.exit(1)

    if args.target:
        targets = [t for t in targets if t.id == args.target]
        if not targets:
            print(f"Target '{args.target}' not found.")
            sys.exit(1)

    with open(config_path, encoding="utf-8") as f:
        config_data = yaml.safe_load(f) or {}

    default_model = config_data.get("model", "claude-haiku-4-5-20251001")
    model = args.model or default_model
    print(f"Model: {model}")

    router = LLMRouter(models=[model])

    if args.dry_run:
        target = targets[0]
        print(f"Dry run: {target.id} with {model}")
        result = await run_dry_scan(target, model, router, config_dir)
        print("Dry run result:")
        for k, v in result.items():
            print(f"  {k}: {v}")
        return

    output_cfg = config_data.get("output", {})
    results_dir = output_cfg.get("results_dir", "results/raw")
    if not os.path.isabs(results_dir):
        results_dir = os.path.join(proj_root, results_dir)

    for target in targets:
        print(f"\n{'='*60}")
        print(f"SCAN: {target.id} ({target.url}) with {model}")
        print(f"{'='*60}")
        start = time.perf_counter()
        try:
            findings, metrics = await run_scan(target, model, router, config_dir)
            duration = time.perf_counter() - start
            model_slug = model.replace("/", "_").replace(".", "_").replace(":", "_")
            filepath = os.path.join(results_dir, f"aiagent_{model_slug}_{target.id}.json")
            output = save_results(filepath, findings, router.get_cost_summary(), target, model, duration, metrics)

            summary = output["summary"]
            meta = output["metadata"]
            print(f"\n{'='*60}")
            print(f"RESULTS: {target.id} with {model}")
            print(f"{'='*60}")
            print(f"  Duration:          {meta['scan_duration_seconds']:.0f}s")
            print(f"  LLM calls:         {meta['llm_calls']}")
            print(f"  Total tokens:      {meta['total_tokens']:,}")
            print(f"  Cost:              ${meta['cost_usd']:.4f}")
            print()
            print(f"  Pages crawled:     {summary['pages_crawled']}")
            print(f"  Forms found:       {summary['forms_found']}")
            print(f"  API endpoints:     {summary['api_endpoints_found']}")
            print(f"  Auth pages:        {summary['auth_pages_detected']}")
            print(f"  Phases completed:  {summary['phases_completed']}")
            print(f"  Tool calls:        {summary['total_tool_calls']}")
            print()
            sev = summary["severity_breakdown"]
            total = summary["total_findings"]
            print(f"  FINDINGS: {total} total")
            print(f"    Critical:        {sev.get('Critical', 0)}")
            print(f"    High:            {sev.get('High', 0)}")
            print(f"    Medium:          {sev.get('Medium', 0)}")
            print(f"    Low:             {sev.get('Low', 0)}")
            print(f"    Informational:   {sev.get('Info', 0)}")
            if summary.get("owasp_breakdown"):
                print(f"\n  OWASP breakdown:")
                for cat, count in sorted(summary["owasp_breakdown"].items()):
                    print(f"    {cat}: {count}")
            if metrics.get("phase_log"):
                print(f"\n  Phase details:")
                for pl in metrics["phase_log"]:
                    print(f"    {pl['phase']:20s} | {pl['tool_calls']:3d} tool calls | {pl['findings']:2d} findings")
            print(f"\n  Results saved to: {filepath}")
        except Exception as e:
            duration = time.perf_counter() - start
            print(f"  ERROR: {e}")
            model_slug = model.replace("/", "_").replace(".", "_").replace(":", "_")
            filepath = os.path.join(results_dir, f"aiagent_{model_slug}_{target.id}.json")
            save_results(filepath, [], router.get_cost_summary(), target, model, duration, {})
            print(f"  Partial results saved to: {filepath}")
            import traceback
            traceback.print_exc()

    print(f"\n{'='*60}")
    print("COST SUMMARY")
    print(f"{'='*60}")
    for row in router.get_cost_summary():
        print(f"  {row['model']}: ${row.get('cost_usd', 0):.4f} USD, {row.get('calls', 0)} calls, {row.get('input_tokens',0)+row.get('output_tokens',0):,} tokens")


if __name__ == "__main__":
    asyncio.run(main())
