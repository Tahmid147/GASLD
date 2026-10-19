# Validation record

The merged scanner passed **29 controlled regression tests**. The exact test names and terminal result are in `evidence/regression-tests.txt`.

The four-commit example produced one unique synthetic secret, two secret-containing blob occurrences, and four expected lifecycle events: introduction, persistence, removal, and subsequent file deletion. Its independently prescribed event labels matched 4/4 and occurrence labels matched 2/2. These are fixture-specific results, not estimates of real-world detection accuracy.

`evidence/experiments.json` contains **42 completed runs**: two traversal baselines, five component ablations, three finite object budgets, two additional content-confidence thresholds, and two additional lineage thresholds, each repeated three times in seeded randomized order. It includes source/manifest hashes, environment details, timing, memory, read counts, coverage and metrics.

The demo's current-only baseline has recall 0 because its final commit contains no secret-bearing file. Full scanning recovers the retained secret. This establishes the constructed traversal difference; it does not establish that lineage improves the underlying regex detector. A–E use the same detector and scan scope, so their detection counts can match.

The suite covers incomplete scans, size/budget limits, unreachable historical objects, detached HEAD, standalone blobs, exact/edited renames, copies and ambiguous sources, branch merges, equal timestamps, truncated ancestry, packing invariance, linked worktrees, bare repositories, binary/ZIP/GZIP extraction, whitespace identity, repeated matches, uncertain metrics, calibration holdout separation, and repeated-snapshot ref changes.

The held-out calibration code was tested with synthetic graded inputs and overlap rejection. **No real-world calibrated weights, empirical novelty claim, universal recall guarantee, or statistical superiority claim is supplied.** Use independent datasets and labels for those conclusions.

Reproduce with `python3 -m unittest -v test_gasld.py`, followed by the demo and benchmark commands in README.md. Python tracing excludes Git child/native memory and adds overhead; tiny-fixture timings should not be extrapolated.
