# GASLD 0.2.0 — merged research prototype

This package extends the supplied 1,381-line `main.py`. The scanner remains a standalone Python file; `research.py` supplies repeatable experiments and `test_gasld.py` supplies controlled regression scenarios. Python 3.10+ and Git on PATH are required. No pip dependencies are needed.

## Start here

```bash
python3 main.py --repo /path/to/repository --scope all --output report.json
```

On Windows, use `python` if that is your Python command. Progress goes to stderr; `--format json` keeps stdout machine-readable. Values are redacted by default. `--no-progress` disables progress messages.

Reproduce the four-commit methodology example:

```bash
python3 research.py demo --out demo
python3 main.py --repo demo/repo --ground-truth demo/ground-truth.json --output demo/rescan.json
```

`demo` must be absent or empty. The generator writes a repository, independent construction-based ground truth, and an actual report. The expected sequence is introduction, persistence, secret removal, then file deletion after removal.

Run the regression suite:

```bash
python3 -m unittest -v test_gasld.py
```

## What changed

| Area | Merged implementation |
| --- | --- |
| Object state | Historical association is independent of reachability. Detached HEAD is included in reachability roots. Linked worktree pack directories are resolved through the common Git directory. |
| Scan completeness | Every blob has an explicit status: text scanned, binary partially scanned, outside scope, budget excluded, size excluded, binary excluded, or read error. Unexamined successors cannot prove removal. |
| Ancestry | All available commits, including unreachable commits, use a topological order. Equal or inconsistent timestamps cannot reorder parents after children. Missing trees fail explicitly. |
| Lineage | Same-path changes, exact moves/copies, and content-similar edited moves/copies. A bounded candidate set and margin check retain ambiguous-source evidence rather than picking arbitrarily. |
| Identity | Internal whitespace remains significant. Multiple source matches are retained. Family grouping requires the same detector, assignment key, inferred file relationship, and string similarity. Replacement is labelled possible; credential rotation is never confirmed. |
| Lifecycle | Parent-specific transitions, unchanged-content persistence, first-observed boundaries, removal, file deletion after prior removal, and retained-object evidence. Merge-parent relationships remain explicit. |
| Propagation | Directed parent-to-child inferred copy/rename edges, possible secret copies into existing files, and ambiguous-source records. Occurrence listings are retained separately. |
| Detection | Existing regex/pattern, entropy, and context scoring; configurable acceptance threshold; custom local rules; synthetic research-secret pattern; exact-value fingerprints. |
| Binary/archive handling | Printable strings plus bounded ZIP/GZIP inspection in memory, with artifact locations. No archive members are written to disk. |
| Risk | Existing six-component formula retained, with experimental interpretation. Cross-branch deletion evidence is constrained by ancestry. Packing no longer influences scan priority. Propagation normalization no longer depends on other secrets' location counts. |
| Evaluation | Unknown predictions remain unjudged; full precision/F1 are withheld when labels are incomplete. Exact event, lineage, propagation, occurrence, and identity-pair metrics; unique-secret Precision@K, Recall@K and nDCG@K. |
| Experiments | Current/reachable baselines, A–E component ablations, object budgets, confidence and lineage sweeps, repeated timings, traced Python memory, and read accounting. |
| Calibration | Seeded weight search on independently labelled training reports, followed by held-out evaluation. Dataset, repository-path and fingerprint overlap checks. |
| Repeated scans | Optional previous-report comparison records removed/moved refs and observed changes in object availability/reachability. |

## Scope and evidence semantics

- `current` means the committed HEAD snapshot. It does not scan uncommitted/untracked working files or the index.
- `reachable` means reachable from all current refs plus HEAD. Reflogs are not roots in this definition.
- `unreachable` means locally present but outside those roots. A reflog-retained object can therefore be classified unreachable.
- `all` enumerates objects actually available in the local object database, including retained unreachable objects. A remote clone does not recover unadvertised server-side objects.
- Historical means association with an available non-HEAD commit. It can coexist with current membership and unreachability. A standalone blob without commit context remains historically unverified.
- Occurrence current/historical labels describe the occurrence's commit; reachability and packing describe the blob. Global object states are in `git_state_snapshot`.
- A removal event means absence of an accepted detector match from fully examined successor text under this configuration. It does not prove that all possible secrets are absent.
- `first_observed`/`last_observed` are recorded commit-time bounds, not credential creation, expiry, revocation, or confirmed exposure duration. Lifecycle order follows ancestry.
- `possible_credential_replacement` does not establish that a provider rotated or revoked a credential. `--rotation-threshold` is retained for CLI compatibility and governs candidate-family string similarity only.

## Research experiments

```bash
python3 research.py benchmark --repo demo/repo --truth demo/ground-truth.json --output experiments.json --budgets 1,2,4 --repeats 3
```

Runs are shuffled using seed 42 by default. Confidence sweeps use 0.4, 0.6, 0.8; lineage sweeps use 0.6, 0.7, 0.8. The default configuration produces 42 runs.

| Model | Active ranking components |
| --- | --- |
| A | Content only |
| B | Content + reachability + history |
| C | B + inferred lineage |
| D | C + propagation |
| E | D + deletion/removal lifecycle evidence |

Weights are renormalized over active components. All ablations use the same object scope and content detector, so identical detection recall is expected unless detector settings or scan scope change. Compare ranking and relationship metrics to assess additional components. The shared graph/snapshot/lifecycle infrastructure is retained; these are not optimized standalone scanner speed comparisons or Gitleaks/TruffleHog benchmarks.

The object budget is applied before detection and lineage content access. Structural Git traversal still happens. Read accounting separates structural bytes, blob reads, and archive expansion. Peak memory is traced Python allocations; it excludes Git subprocess and native memory. Profiling overhead is included equally. Timings do not include final JSON file serialization. Repeated small-fixture results cannot establish performance on large repositories.

## Ground-truth format

```json
{
  "schema": "gasld-ground-truth-v2",
  "dataset_id": "independently-verified-repository-01",
  "complete": false,
  "unlisted_policy": "unjudged",
  "items": [
    {"id": "S1", "value": "exact extracted synthetic credential", "expected_secret": true, "relevance": 3},
    {"id": "N1", "value": "known synthetic nonsecret", "expected_secret": false, "relevance": 0}
  ]
}
```

A full SHA256 `fingerprint` may replace `value`. Fingerprints use exact extracted values (PEM CRLF line endings are normalized). Old fingerprints that removed meaningful spaces must be regenerated. Exact identity is independent of the rule that matched. IDs are deterministic fingerprint prefixes.

Only use `complete: true` and `unlisted_policy: "negative"` when ground truth is independently exhaustive for the intended scope. Otherwise unlisted detections are reported as unjudged; precision and F1 are null, with bounds and a clearly labelled judged-subset precision. Recall is recall over known positive labels. Duplicate identity labels are rejected; use `occurrences` for multiple locations.

Optional independently labelled arrays:

| Array | Required matching fields |
| --- | --- |
| `events` | `fingerprint`, `event`, `commit`, `parent_commit`, `path` |
| `lineage` | `source_blob`, `target_blob`, `source_commit`, `target_commit`, `source_path`, `target_path` |
| `propagation` | `fingerprint`, `source_commit`, `target_commit`, `source_path`, `target_path`, `kind` |
| `occurrences` | `fingerprint`, `blob_oid`, `commit`, `path` |
| `identity_pairs` | `a` fingerprint, `b` fingerprint, boolean `same_family` |

For the first four arrays, set `<name>_complete: true` only when all valid predictions have been independently enumerated. Otherwise unmatched predictions remain unjudged. Structured matching uses the exact listed fields. Positive identity pairs with missing members count as FN; missing pairs are also reported unresolved.

Ranking uses one result per secret, taking the maximum occurrence score, with fingerprint tie-breaking. Labels use graded relevance 0–4. Fixed K is the Precision@K denominator; empty ranks count against precision. If top-K results contain unjudged credentials, the corresponding complete ranking metrics are withheld and precision bounds shown. These values describe the supplied judgement pool, not automatically all repository exposures.

## Held-out rank calibration

Generate full-model reports for separate labelled train/test repositories. Their manifests must contain `split: "train"` or `split: "test"`, a distinct `dataset_id`, and independent relevance labels for all ranked secrets. Each dataset needs at least two relevance grades.

```bash
python3 research.py calibrate --train train-report.json train-truth.json --test test-report.json test-truth.json --output calibrated-risk.json --trials 200 --seed 42
python3 main.py --repo /path/to/repo --risk-config calibrated-risk.json --output ranked.json
```

Repeat `--train`/`--test` for multiple report-manifest pairs. Candidate weights are selected by mean training nDCG@5; held-out labels do not select weights. The output compares default and selected weights on the test set. Dataset IDs, repository paths, and credential identities must not overlap; the researcher must additionally prevent fork/history leakage. Do not tune repeatedly on the holdout. Severity category cutoffs remain experimental; this does not calibrate compromise probabilities.

No calibrated real-world weights are bundled: independent real-world relevance labels were not supplied. The regression suite verifies calibration plumbing with synthetic graded inputs only.

## Extra options

```bash
python3 main.py --repo /path/to/repo --scope all --object-budget 1000 --max-blob-size 10MiB --min-confidence 0.6 --output bounded.json
python3 main.py --repo /path/to/repo --previous-report earlier.json --output later.json
```

Previous-report comparison requires v2 snapshots from the same local repository path. A moved ref is not proof of deleted commits; a missing object does not identify its removal mechanism. Reports do not prove the path was not replaced with a different repository between scans.

Custom patterns extend the built-in rules:

```json
{"rules":[{"name":"lab_rule","regex":"LAB_SECRET_[A-Z0-9]{32}","group":0,"pattern_score":1.0}]}
```

Use `--rules custom-rules.json`. Regex, scores, and groups are validated when loaded; regex execution is not sandboxed. Use locally reviewed rules.

## Remaining research limits

This is an implemented research prototype, not demonstrated research novelty or a production certification. The provider rules and heuristics are not exhaustive or empirically calibrated. Current-state coverage does not include working files. Single-snapshot analysis cannot reconstruct missing branch-deletion events without earlier evidence. Missing objects cannot be recovered by this code.

Lineage compares a 200,000-character prefix and up to 64 source paths per new path by default (`--max-lineage-candidates`). It is approximate; repeated/ambiguous files may remain unresolved. Renames after secret removal can be tracked when there is sufficient inferred file continuity. Multiple simultaneous source copies can remain ambiguous. Binary/ZIP/GZIP analysis is explicitly partial: other formats and encodings are unsupported, nesting is limited to two extraction levels, at most 100 ZIP entries are considered, and expansion is bounded by the blob-size limit. No binary absence is used as proof of secret removal.

Lifecycle snapshots and occurrence evidence can use substantial memory on large histories. No universal efficiency or recall guarantee is made. Controlled tests establish behavior for their constructed cases; broader datasets, verified baseline tools, calibration, literature review, and statistical research conclusions remain empirical work.
