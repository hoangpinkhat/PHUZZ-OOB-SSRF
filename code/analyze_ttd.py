"""
analyze_ttd.py — Measure Time-to-Detection (TTD) for SSRF findings in PHUZZ output.

How it works:
  - coverage_id format: "<unix_timestamp>-<uuid>"
  - Fuzzer start time  ≈ min timestamp of parent candidates (initial seeds)
  - First SSRF time    = min timestamp among all SSRF findings
  - TTD = first_ssrf_time - fuzzer_start_time

Usage:
  python analyze_ttd.py
  python analyze_ttd.py --output-dir /path/to/fuzzer/output
"""

import argparse
import glob
import json
import os
import re
from datetime import datetime, timezone


def ts(cov_id: str) -> int | None:
    """Extract Unix timestamp from the coverage_id prefix."""
    try:
        return int(cov_id.split("-")[0])
    except Exception:
        return None


def analyze(output_dir: str) -> list[dict]:
    results = []

    pattern = os.path.join(output_dir, "**", "vulnerable-candidates.json")
    for vuln_file in sorted(glob.glob(pattern, recursive=True)):
        run_dir = os.path.dirname(vuln_file)
        label = (
            run_dir
            .replace(output_dir.rstrip("/\\") + os.sep, "")
            .replace("\\", "/")
        )

        try:
            with open(vuln_file, encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            results.append({"label": label, "note": f"parse error: {exc}"})
            continue

        ssrf_list = data.get("SSRF", [])
        if not ssrf_list:
            results.append({"label": label, "note": "no SSRF findings"})
            continue

        first_ssrf_ts = min(
            t for e in ssrf_list if (t := ts(e["coverage_id"])) is not None
        )
        num_findings = len(ssrf_list)

        # Start time: earliest parent timestamp (initial seed)
        parent_ts_list = [
            t for e in ssrf_list
            if (t := ts(e.get("parent", ""))) is not None
        ]
        start_ts = min(parent_ts_list) if parent_ts_list else first_ssrf_ts

        # Also scan individual SSRF-<timestamp>-*.json files (written by SSRFVulnCheck)
        ssrf_files = glob.glob(os.path.join(run_dir, "SSRF-*.json"))
        if ssrf_files:
            file_ts_list = []
            for sf in ssrf_files:
                m = re.search(r"SSRF-(\d+)-", os.path.basename(sf))
                if m:
                    file_ts_list.append(int(m.group(1)))
            if file_ts_list:
                first_ssrf_ts = min(first_ssrf_ts, min(file_ts_list))

        ttd_sec = first_ssrf_ts - start_ts

        # Extract first SSRF entry for detail
        first = min(ssrf_list, key=lambda e: ts(e["coverage_id"]) or int(9e18))
        payload = ""
        for pt in ("query_params", "body_params", "headers"):
            fp = first.get("fuzz_params", {}).get(pt, {})
            if fp:
                payload = str(list(fp.values())[0])[:60]
                break

        results.append({
            "label":         label,
            "start_time":    datetime.fromtimestamp(start_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "first_ssrf":    datetime.fromtimestamp(first_ssrf_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "ttd_sec":       ttd_sec,
            "num_findings":  num_findings,
            "param":         first.get("mutated_param_name", ""),
            "first_payload": payload,
        })

    return results


def fmt_ttd(sec: int) -> str:
    if sec < 60:
        return f"{sec}s"
    return f"{sec // 60}m {sec % 60:02d}s"


def print_table(results: list[dict]) -> None:
    print(
        f"{'Target':<38} {'Start (UTC)':<21} {'First SSRF (UTC)':<21}"
        f" {'TTD':>8} {'#':>5}  Param / First Payload"
    )
    print("-" * 145)
    for r in results:
        if "note" in r:
            print(f"{r['label']:<38}  ({r['note']})")
            continue
        print(
            f"{r['label']:<38} {r['start_time']:<21} {r['first_ssrf']:<21}"
            f" {fmt_ttd(r['ttd_sec']):>8} {r['num_findings']:>5}"
            f"  [{r['param']}] {r['first_payload']}"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure SSRF Time-to-Detection from PHUZZ output.")
    parser.add_argument(
        "--output-dir",
        default=os.path.join(os.path.dirname(__file__), "fuzzer", "output"),
        help="Path to fuzzer output directory (default: ./fuzzer/output)",
    )
    args = parser.parse_args()

    results = analyze(args.output_dir)
    print_table(results)


if __name__ == "__main__":
    main()
