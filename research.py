#!/usr/bin/env python3
"""Reproducible GASLD demo, baselines/ablations/budgets, and held-out rank calibration.
Standard library only. Relevance labels must be independently supplied, never
calculated from GASLD's own risk formula. This tool cannot establish novelty.
"""
from __future__ import annotations
import argparse
import json
import math
import os
from pathlib import Path
import random
import statistics
import subprocess
import sys
import time
import main as gasld


def dump(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def scan(repo, scope="all", model="E", budget=0, confidence=.40, lineage=.70):
    repository = gasld.GitRepo(Path(repo)); repository.validate()
    engine = gasld.Engine(repository, scope=scope, max_blob_size=gasld.MAX_BLOB_DEFAULT,
        include_binary_strings=True, object_budget=budget, max_commits=0,
        content_weights=gasld.CONTENT_WEIGHTS_DEFAULT, lineage_weights=gasld.LINEAGE_WEIGHTS_DEFAULT,
        risk_weights=gasld.RISK_WEIGHTS_DEFAULT, lineage_threshold=lineage,
        rotation_threshold=gasld.ROTATION_THRESHOLD_DEFAULT, min_confidence=confidence, model=model)
    start = time.perf_counter(); gasld.run_engine(engine)
    return engine.report(str(repo), [], gasld.now_iso(), time.perf_counter() - start, False, None)


def demo(dest):
    dest = Path(dest).resolve()
    if dest.exists() and any(dest.iterdir()):
        raise ValueError("Demo directory must be absent or empty")
    dest.mkdir(parents=True, exist_ok=True)
    repo = dest / "repo"; repo.mkdir()
    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout.strip()
    git("init", "-b", "main"); git("config", "user.name", "GASLD Synthetic Lab"); git("config", "user.email", "lab@example.invalid")
    secret = "RESEARCH_SECRET_" + "A1B2C3D4" * 4
    fp = gasld.fingerprint(secret)
    bodies = [f'API_KEY="{secret}"\nDEBUG=false\n', f'API_KEY="{secret}"\nDEBUG=true\n', 'DEBUG=true\n', None]
    commits, blobs = [], []
    for i, body in enumerate(bodies):
        file = repo / "config.env"
        if body is None:
            file.unlink()
        else:
            file.write_text(body)
        git("add", "-A")
        env = os.environ.copy(); env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = f"2025-01-0{i+1}T12:00:00+00:00"
        subprocess.run(["git", "-C", str(repo), "commit", "-m", f"Scenario step {i+1}"], env=env, capture_output=True, check=True)
        commits.append(git("rev-parse", "HEAD"))
        blobs.append(git("rev-parse", "HEAD:config.env") if body is not None else None)
    # Expected labels are prescribed from construction, never from scanner output.
    names = ["introduction", "persistence", "secret_removed", "file_deleted_after_removal"]
    events = [{"fingerprint": fp, "event": name, "commit": commits[i], "parent_commit": commits[i-1] if i else None, "path": "config.env"} for i, name in enumerate(names)]
    truth = {"schema": "gasld-ground-truth-v2", "dataset_id": "four-commit-synthetic-demo", "complete": True, "unlisted_policy": "negative", "label_basis": "Synthetic construction; illustrative relevance is not a real-world risk label", "items": [{"id": "S1", "value": secret, "expected_secret": True, "relevance": 2}], "events_complete": True, "events": events, "occurrences_complete": True, "occurrences": [{"fingerprint": fp, "commit": commits[i], "path": "config.env", "blob_oid": blobs[i]} for i in (0, 1)]}
    dump(dest / "ground-truth.json", truth)
    report = scan(repo)
    report["ground_truth_evaluation"] = gasld.evaluate_report(report, truth)
    dump(dest / "report.json", report)
    return {"repo": str(repo), "ground_truth": str(dest / "ground-truth.json"), "report": str(dest / "report.json"), "evaluation": report["ground_truth_evaluation"]}


def interval(values, rng):
    if len(values) < 2:
        return {"mean": statistics.mean(values), "bootstrap_95_percent_interval": None}
    means = sorted(statistics.mean(rng.choices(values, k=len(values))) for _ in range(500))
    return {"mean": statistics.mean(values), "bootstrap_95_percent_interval": [means[12], means[487]]}


def benchmark(repo, truth_path, output, budgets, repeats=3, seed=42, confidences=(.4, .6, .8), lineages=(.6, .7, .8)):
    if repeats < 1 or any(b < 1 for b in budgets):
        raise ValueError("Repeats and finite budgets must be positive")
    if any(not math.isfinite(x) or not 0 <= x <= 1 for x in [*confidences, *lineages]):
        raise ValueError("Sweep thresholds must be within [0,1]")
    truth = json.loads(Path(truth_path).read_text()); gasld.validate_manifest(truth)
    cases = [("baseline_current", "current", "A", 0, .4, .7), ("baseline_reachable", "reachable", "A", 0, .4, .7)]
    cases += [(f"ablation_{m}", "all", m, 0, .4, .7) for m in "ABCDE"]
    cases += [(f"budget_{b}", "all", "E", b, .4, .7) for b in budgets]
    cases += [(f"confidence_{c}", "all", "E", 0, c, .7) for c in confidences if c != .4]
    cases += [(f"lineage_{l}", "all", "E", 0, .4, l) for l in lineages if l != .7]
    jobs = [(case, repeat) for case in cases for repeat in range(repeats)]
    rng = random.Random(seed); rng.shuffle(jobs)
    rows = []
    for i, (case, repeat) in enumerate(jobs, 1):
        name, scope, model, budget, confidence, lineage = case
        print(f"Experiment {i}/{len(jobs)}: {name} repeat {repeat+1}", file=sys.stderr, flush=True)
        report = scan(repo, scope, model, budget, confidence, lineage)
        rows.append({"case": name, "repeat": repeat, "scope": scope, "model": model, "budget": budget, "min_confidence": confidence, "lineage_threshold": lineage, "duration_seconds": report["duration_seconds"], "peak_python_memory_bytes": report["peak_python_memory_bytes"], "io_accounting": report["io_accounting"], "phase_seconds": report["phase_seconds"], "coverage": report["coverage"]["scan_status_counts"], "evaluation": gasld.evaluate_report(report, truth)})
    summary = {}
    for name, *_ in cases:
        runs = [r for r in rows if r["case"] == name]
        summary[name] = {"duration_seconds": interval([r["duration_seconds"] for r in runs], rng), "recall": runs[0]["evaluation"]["recall"], "precision": runs[0]["evaluation"]["precision"], "peak_python_memory_bytes_max": max(r["peak_python_memory_bytes"] for r in runs), "blob_reads": runs[0]["io_accounting"].get("blob_reads_total", 0)}
    full = summary["ablation_E"]["recall"]
    for value in summary.values():
        value["recall_difference_from_full"] = value["recall"] - full if value["recall"] is not None and full is not None else None
    result = {"schema": "gasld-experiments-v1", "seed": seed, "repeats": repeats, "repository": str(Path(repo).resolve()), "dataset_id": truth.get("dataset_id"), "scanner_version": gasld.VERSION, "scanner_source_sha256": gasld.sha256(Path(gasld.__file__).read_bytes()).hexdigest(), "ground_truth_sha256": gasld.sha256(Path(truth_path).read_bytes()).hexdigest(), "python_version": sys.version, "git_version": subprocess.run(["git", "--version"],capture_output=True,text=True,check=True).stdout.strip(), "notes": ["A=content; B adds reachability/history; C adds inferred lineage; D adds propagation; E adds deletion/removal evidence.", "All ablations share detector and object scope. Detection counts may be identical; ranking/relationship metrics measure added value.", "Shared graph/snapshot/lifecycle infrastructure is retained in all models. These are component/score ablations, not optimized standalone scanner speed comparisons.", "Budgets constrain detection reads before lineage; structural traversal still visits all acquired objects.", "Memory is peak traced Python allocations, excludes Git subprocess/native memory. Profiling overhead is included in all timings.", "Bootstrap intervals describe repeated timings on this machine; they do not establish generalization or statistical superiority.", "Externally supplied labels must be independently verified. Synthetic results do not establish real-world ranking quality."], "summary": summary, "runs": rows}
    dump(output, result); return result


COMPONENTS = {"content": "content_confidence", "reachability": "reachability_score", "deletion": "deletion_score", "historical": "historical_score", "lineage": "lineage_score", "propagation": "propagation_score"}


def ranked_with_weights(report, weights):
    scores = {}
    for row in report["prioritized_findings"]:
        v = sum(weights[k] * row[column] for k, column in COMPONENTS.items())
        scores[row["fingerprint"]] = max(scores.get(row["fingerprint"], 0), v)
    return sorted(scores, key=lambda fp: (-scores[fp], fp))


def calibrate(train_pairs, test_pairs, output, trials=200, seed=42):
    if trials < 1:
        raise ValueError("trials must be positive")
    def load(pairs, split):
        rows = []
        for report_path, truth_path in pairs:
            report = json.loads(Path(report_path).read_text()); truth = json.loads(Path(truth_path).read_text())
            if truth.get("split") != split or not truth.get("dataset_id"):
                raise ValueError(f"Calibration manifest needs split={split} and an independent dataset_id")
            labels = gasld.validate_manifest(truth)
            ranked = ranked_with_weights(report, gasld.RISK_WEIGHTS_DEFAULT)
            if not ranked or any(fp not in labels or "relevance" not in labels[fp] for fp in ranked):
                raise ValueError("Every ranked credential needs an independent relevance label")
            if len({row.get("relevance") for row in labels.values()}) < 2:
                raise ValueError("Calibration needs at least two relevance grades per dataset")
            rows.append((report, truth, labels))
        return rows
    training, testing = load(train_pairs, "train"), load(test_pairs, "test")
    if not training or not testing:
        raise ValueError("Separate training and held-out test datasets are required")
    train_ids = {truth["dataset_id"] for _, truth, _ in training}
    test_ids = {truth["dataset_id"] for _, truth, _ in testing}
    train_fps = set().union(*(set(labels) for _, _, labels in training))
    test_fps = set().union(*(set(labels) for _, _, labels in testing))
    train_repos = {r.get("repository_path") for r, _, _ in training}
    test_repos = {r.get("repository_path") for r, _, _ in testing}
    if train_ids & test_ids or train_fps & test_fps or train_repos & test_repos:
        raise ValueError("Train/test overlap in dataset IDs, repository paths, or credential identities")
    def objective(rows, weights):
        scores = []
        for report, _, labels in rows:
            score = gasld.ranking_metrics(ranked_with_weights(report, weights), labels)["metrics"]["5"]["ndcg_at_k"]
            if score is None:
                raise ValueError("nDCG@5 requires positive independent relevance labels")
            scores.append(score)
        return statistics.mean(scores)
    rng = random.Random(seed)
    candidates = [dict(gasld.RISK_WEIGHTS_DEFAULT)]
    for _ in range(trials):
        raw = {k: rng.expovariate(1) for k in COMPONENTS}; total = sum(raw.values())
        candidates.append({k: v / total for k, v in raw.items()})
    best = max(candidates, key=lambda w: objective(training, w))
    # Held-out labels are not consulted during candidate selection.
    result = {"schema": "gasld-rank-config-v1", "risk_weights": best, "seed": seed, "candidates": len(candidates), "objective": "mean repository nDCG@5", "training_dataset_ids": sorted(train_ids), "held_out_dataset_ids": sorted(test_ids), "training_ndcg_at_5": objective(training, best), "held_out_ndcg_at_5": objective(testing, best), "held_out_default_ndcg_at_5": objective(testing, gasld.RISK_WEIGHTS_DEFAULT), "limitations": ["Ranks exposures; does not calibrate compromise probabilities or severity thresholds.", "Do not repeatedly tune against this test set; reserve a new holdout after adaptive changes.", "Identity/path checks do not replace independent repository/fork separation by the researcher."]}
    dump(output, result); return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("demo"); p.add_argument("--out", required=True)
    p = sub.add_parser("benchmark"); p.add_argument("--repo", required=True); p.add_argument("--truth", required=True); p.add_argument("--output", required=True); p.add_argument("--budgets", default="1,2,4"); p.add_argument("--repeats", type=int, default=3); p.add_argument("--seed", type=int, default=42)
    p = sub.add_parser("calibrate"); p.add_argument("--train", nargs=2, action="append", required=True, metavar=("REPORT", "TRUTH")); p.add_argument("--test", nargs=2, action="append", required=True, metavar=("REPORT", "TRUTH")); p.add_argument("--output", required=True); p.add_argument("--trials", type=int, default=200); p.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    try:
        if args.command == "demo":
            result = demo(args.out); print(json.dumps(result, indent=2))
        elif args.command == "benchmark":
            result = benchmark(args.repo, args.truth, args.output, [int(x) for x in args.budgets.split(",")], args.repeats, args.seed); print(json.dumps(result["summary"], indent=2))
        else:
            print(json.dumps(calibrate(args.train, args.test, args.output, args.trials, args.seed), indent=2))
        return 0
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError, gasld.GitError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr); return 2


if __name__ == "__main__":
    raise SystemExit(main())
