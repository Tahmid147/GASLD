#!/usr/bin/env python3
"""
GASLD — Git-Aware Secret Lifecycle Detection
Single-file research prototype based on the uploaded GASLD methodology.

Pipeline:
  Repository acquisition
  -> complete Git object extraction
  -> object graph construction
  -> reachability / historical / deletion / packing analysis
  -> blob lineage inference
  -> secret detection (pattern + entropy + context)
  -> secret identity/correlation
  -> lifecycle construction
  -> propagation analysis
  -> Git-aware risk scoring
  -> risk prioritization
  -> optional ground-truth evaluation

Research note:
The methodology explicitly treats thresholds/weights as experimental parameters.
Defaults in this file are therefore starting values for experiments, not
scientifically established constants.

Use only on repositories you own or are authorized to assess.
Raw secret values are redacted by default and credentials are never validated
against external services.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from difflib import SequenceMatcher
from hashlib import sha256
import json
import gzip
import io
import zipfile
import heapq
import tracemalloc
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any, Iterable


NAME = "GASLD"
VERSION = "0.2.0-research"
MAX_BLOB_DEFAULT = 10 * 1024 * 1024

# GASLD PDF initial experimental risk configuration.
RISK_WEIGHTS_DEFAULT = {
    "content": 0.30,
    "reachability": 0.15,
    "deletion": 0.15,
    "historical": 0.10,
    "lineage": 0.15,
    "propagation": 0.15,
}

# The PDF defines these components but not universal weights.
CONTENT_WEIGHTS_DEFAULT = {"pattern": 0.50, "entropy": 0.20, "context": 0.30}
LINEAGE_WEIGHTS_DEFAULT = {"content": 0.45, "path": 0.25, "commit": 0.20, "temporal": 0.10}
LINEAGE_THRESHOLD_DEFAULT = 0.70
ROTATION_THRESHOLD_DEFAULT = 0.82
RISK_THRESHOLDS_DEFAULT = {"critical": 0.85, "high": 0.70, "medium": 0.50}

POSITIVE_CONTEXT = {
    "api_key", "apikey", "secret", "client_secret", "access_token", "auth_token",
    "password", "passwd", "pwd", "credential", "private_key", "token", "bearer",
    "authorization", "aws_access_key_id", "aws_secret_access_key", "database_url",
    "db_password",
}
NEGATIVE_CONTEXT = {
    "example", "sample", "dummy", "placeholder", "fake", "testing", "test",
    "changeme", "your_key_here", "redacted", "documentation", "fixture", "mock",
}


def clamp01(v: float) -> float:
    return max(0.0, min(1.0, float(v)))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_size(value: str) -> int:
    m = re.fullmatch(r"(?i)\s*(\d+)\s*(b|[kmgt](?:i?b)?)?\s*", value)
    if not m:
        raise argparse.ArgumentTypeError("Use bytes or values like 10MiB, 512K, 2GiB")
    n = int(m.group(1))
    suffix = (m.group(2) or "").lower().removesuffix("b").removesuffix("i")
    return n * (1024 ** {"": 0, "k": 1, "m": 2, "g": 3, "t": 4}[suffix])


def human_bytes(v: int) -> str:
    n = float(v)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.2f} {unit}"
        n /= 1024
    return str(v)


def normalize_secret(value: str) -> str:
    # Values have already been extracted from their syntax. Internal spaces are significant.
    return value.replace("\r\n", "\n") if value.startswith("-----BEGIN ") else value


def fingerprint(value: str) -> str:
    return sha256(normalize_secret(value).encode("utf-8", errors="ignore")).hexdigest()


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def entropy_score(text: str) -> float:
    # Engineering normalization. Entropy remains supporting evidence only.
    return clamp01((shannon_entropy(text) - 3.0) / 2.5)


def risk_class(score: float) -> str:
    if score >= RISK_THRESHOLDS_DEFAULT["critical"]:
        return "critical"
    if score >= RISK_THRESHOLDS_DEFAULT["high"]:
        return "high"
    if score >= RISK_THRESHOLDS_DEFAULT["medium"]:
        return "medium"
    return "low"


def redact(value: str, show: bool) -> str:
    if show:
        return value
    if len(value) <= 8:
        return "[REDACTED]"
    return f"{value[:3]}…{value[-3:]} [REDACTED]"


def parse_weights(spec: str, keys: tuple[str, ...]) -> dict[str, float]:
    out: dict[str, float] = {}
    for item in spec.split(","):
        k, sep, v = item.partition("=")
        if not sep or k.strip() not in keys:
            raise argparse.ArgumentTypeError(f"Invalid weight component: {item}")
        if k.strip() in out:
            raise argparse.ArgumentTypeError("Duplicate weight component")
        number = float(v)
        if not math.isfinite(number) or number < 0:
            raise argparse.ArgumentTypeError("Weights must be finite and nonnegative")
        out[k.strip()] = number
    if set(out) != set(keys):
        raise argparse.ArgumentTypeError(f"Required keys: {', '.join(keys)}")
    total = sum(out.values())
    if not math.isfinite(total) or total <= 0:
        raise argparse.ArgumentTypeError("Weights must sum to a positive value")
    return {k: out[k] / total for k in keys}


@dataclass(slots=True)
class GitObject:
    oid: str
    obj_type: str
    size: int
    reachable: bool = False
    current: bool = False
    historical: bool = False
    unreachable: bool = False
    packed: bool = False
    refs: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CommitInfo:
    oid: str
    tree: str | None
    parents: list[str]
    timestamp: int


@dataclass(slots=True)
class TreeEntry:
    mode: str
    obj_type: str
    oid: str
    name: str


@dataclass(slots=True)
class PathChange:
    parent: str | None
    commit: str
    timestamp: int
    path: str
    old_blob: str | None
    new_blob: str | None
    event: str
    old_path: str | None = None


@dataclass(slots=True)
class LineageEdge:
    source_blob: str
    target_blob: str
    source_path: str
    target_path: str
    source_commit: str | None
    target_commit: str
    content_similarity: float
    path_similarity: float
    commit_similarity: float
    temporal_similarity: float
    confidence: float


@dataclass(slots=True)
class Detection:
    detector: str
    value: str
    normalized: str
    fingerprint: str
    line: int
    column: int
    pattern_score: float
    entropy_score: float
    context_score: float
    content_confidence: float
    binary_extracted: bool = False
    context_key: str = ""
    artifact: str = "blob"


@dataclass(slots=True)
class LifecycleEvent:
    secret_id: str
    event: str
    commit: str | None
    timestamp: int | None
    path: str | None
    blob_oid: str | None
    details: str
    confidence: float = 1.0
    parent_commit: str | None = None
    related_path: str | None = None
    evidence_status: str = "observed"


@dataclass(slots=True)
class Occurrence:
    secret_id: str
    family_id: str
    detector: str
    fingerprint: str
    blob_oid: str
    path: str
    commit: str | None
    timestamp: int | None
    current: bool
    reachable: bool
    historical: bool
    packed: bool
    content_confidence: float
    reachability_score: float = 0.0
    deletion_score: float = 0.0
    historical_score: float = 0.0
    lineage_score: float = 0.0
    propagation_score: float = 0.0
    final_risk: float = 0.0
    risk_class: str = "low"
    evidence: list[str] = field(default_factory=list)


class GitError(RuntimeError):
    pass


class GitRepo:
    def __init__(self, path: Path):
        self.path = path.resolve()
        self._git_dir: Path | None = None
        self._format: str | None = None

    def run(self, args: list[str], check: bool = True) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_NO_REPLACE_OBJECTS"] = "1"
        env["GIT_NO_LAZY_FETCH"] = "1"
        cp = subprocess.run(
            ["git", "-C", str(self.path), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
        )
        if check and cp.returncode != 0:
            raise GitError(cp.stderr.decode("utf-8", errors="replace").strip())
        return cp

    def text(self, args: list[str], check: bool = True) -> str:
        return self.run(args, check).stdout.decode("utf-8", errors="replace")

    def validate(self) -> None:
        if not self.path.is_dir():
            raise FileNotFoundError(f"Repository not found: {self.path}")
        self.run(["rev-parse", "--git-dir"])

    @property
    def git_dir(self) -> Path:
        if self._git_dir is None:
            p = Path(self.text(["rev-parse", "--git-dir"]).strip())
            self._git_dir = p if p.is_absolute() else (self.path / p).resolve()
        return self._git_dir

    @property
    def object_format(self) -> str:
        if self._format is None:
            cp = self.run(["rev-parse", "--show-object-format"], check=False)
            fmt = cp.stdout.decode().strip() if cp.returncode == 0 else "sha1"
            self._format = fmt if fmt in {"sha1", "sha256"} else "sha1"
        return self._format

    @property
    def raw_oid_len(self) -> int:
        return 32 if self.object_format == "sha256" else 20

    def refs(self) -> dict[str, str]:
        out = {}
        for line in self.text(["for-each-ref", "--format=%(refname)%00%(objectname)"]).splitlines():
            if "\x00" in line:
                ref, oid = line.split("\x00", 1)
                out[ref] = oid
        return out

    def head(self) -> str | None:
        cp = self.run(["rev-parse", "--verify", "HEAD"], check=False)
        return cp.stdout.decode().strip() if cp.returncode == 0 else None


class BatchReader:
    def __init__(self, repo: GitRepo):
        self.repo = repo
        self.proc: subprocess.Popen | None = None

    def __enter__(self):
        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_NO_REPLACE_OBJECTS"] = "1"
        env["GIT_NO_LAZY_FETCH"] = "1"
        self.proc = subprocess.Popen(
            ["git", "-C", str(self.repo.path), "cat-file", "--batch"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env
        )
        return self

    def __exit__(self, *_):
        if self.proc:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.terminate()
            try:
                self.proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
            finally:
                if self.proc.stdout:
                    self.proc.stdout.close()
                if self.proc.stderr:
                    self.proc.stderr.close()

    def read(self, oid: str) -> tuple[str, bytes]:
        assert self.proc and self.proc.stdin and self.proc.stdout
        self.proc.stdin.write((oid + "\n").encode())
        self.proc.stdin.flush()
        header = self.proc.stdout.readline().rstrip(b"\n").split()
        if len(header) != 3:
            raise GitError(f"Unable to read object {oid}")
        obj_type = header[1].decode()
        size = int(header[2])
        data = self.proc.stdout.read(size)
        delimiter = self.proc.stdout.read(1)
        if len(data) != size or delimiter != b"\n":
            raise GitError(f"Truncated object {oid}")
        return obj_type, data


def is_remote(value: str) -> bool:
    return value.startswith(("http://", "https://", "ssh://", "git://")) or (
        "@" in value and ":" in value and not Path(value).exists()
    )


def acquire(target: str) -> tuple[Path, tempfile.TemporaryDirectory | None, list[str]]:
    if not is_remote(target):
        return Path(target).expanduser().resolve(), None, []
    tmp = tempfile.TemporaryDirectory(prefix="gasld_")
    dest = Path(tmp.name) / "repo"
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    cp = subprocess.run(
        ["git", "clone", "--quiet", "--no-single-branch", target, str(dest)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False
    )
    if cp.returncode != 0:
        tmp.cleanup()
        raise GitError(cp.stderr.decode("utf-8", errors="replace").strip())
    return dest, tmp, [
        "Remote clone contains only objects transferred by the server; server-side unreachable objects are not guaranteed."
    ]


@dataclass(slots=True)
class Rule:
    name: str
    regex: re.Pattern[str]
    pattern_score: float
    group: int = 0


def build_rules() -> list[Rule]:
    rules: list[Rule] = []
    def add(name: str, p: str, score: float, group: int = 0):
        rules.append(Rule(name, re.compile(p, re.I | re.M), score, group))

    # Built-in pattern heuristics; not a claim of exhaustive provider coverage.
    add("aws_access_key_id", r"\bAKIA[0-9A-Z]{16}\b", 0.98)
    add("google_api_key", r"\bAIza[0-9A-Za-z\-_]{35}\b", 0.98)
    add("stripe_live_secret", r"\bsk_live_[0-9A-Za-z]{24,}\b", 0.98)
    add("stripe_restricted_key", r"\brk_live_[0-9A-Za-z]{24,}\b", 0.98)
    add("twilio_api_key", r"\bSK[0-9a-fA-F]{32}\b", 0.96)
    add("mailgun_api_key", r"\bkey-[0-9A-Za-z]{32}\b", 0.95)
    add("mailchimp_api_key", r"\b[0-9a-f]{32}-us[0-9]{1,2}\b", 0.95)
    add("square_access_token", r"\bsq0atp-[0-9A-Za-z\-_]{22}\b", 0.96)
    add("square_oauth_secret", r"\bsq0csp-[0-9A-Za-z\-_]{43}\b", 0.96)
    add("amazon_mws_auth_token", r"\bamzn\.mws\.[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\b", 0.98)
    add("twitter_access_token", r"\b[1-9][0-9]+-[0-9A-Za-z]{40}\b", 0.93)
    add("private_key_block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]{32,}?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY(?: BLOCK)?-----", 0.99)

    # Generic context-aware fallbacks for secrets without a fixed vendor signature.
    add(
        "generic_credential_assignment",
        r"\b(?:api[_-]?key|secret|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|pwd|private[_-]?key|database[_-]?url|db[_-]?password)\b\s*[:=]\s*[\"'`]([^\"'`\r\n]{8,512})[\"'`]",
        0.70, 1
    )
    add("bearer_token", r"\b(?:authorization\s*[:=]\s*[\"'`]?)bearer\s+([A-Za-z0-9._~+/=-]{16,2048})", 0.78, 1)
    add("research_secret", r"\bRESEARCH_SECRET_[A-Z0-9]{32}\b", 1.0)
    return rules


class Engine:
    def __init__(
        self,
        repo: GitRepo,
        *,
        scope: str,
        max_blob_size: int,
        include_binary_strings: bool,
        object_budget: int,
        max_commits: int,
        content_weights: dict[str, float],
        lineage_weights: dict[str, float],
        risk_weights: dict[str, float],
        lineage_threshold: float,
        rotation_threshold: float,
        min_confidence: float = 0.40,
        model: str = "E",
        progress: bool = False,
        max_lineage_candidates: int = 64,
        custom_rules: Path | None = None,
    ):
        self.repo = repo
        self.scope = scope
        self.max_blob_size = max_blob_size
        self.include_binary_strings = include_binary_strings
        self.object_budget = object_budget
        self.max_commits = max_commits
        self.content_weights = content_weights
        self.lineage_weights = lineage_weights
        self.risk_weights = risk_weights
        self.lineage_threshold = lineage_threshold
        self.rotation_threshold = rotation_threshold
        self.min_confidence = min_confidence
        self.model = model
        self.progress = progress
        self.max_lineage_candidates = max_lineage_candidates
        self.scan_status: dict[str, str] = {}
        self.propagation_edges: list[dict[str, Any]] = []
        self.uncertain_transitions: list[dict[str, Any]] = []
        self.phase_seconds: dict[str, float] = {}
        self.warnings: list[str] = []
        self.peak_memory_bytes = 0
        self._last_progress = 0.0

        self.objects: dict[str, GitObject] = {}
        self.refs: dict[str, str] = {}
        self.head_oid: str | None = None
        self.reachable: set[str] = set()
        self.current: set[str] = set()
        self.packed: set[str] = set()

        self.commits: dict[str, CommitInfo] = {}
        self.trees: dict[str, list[TreeEntry]] = {}
        self.tags: dict[str, str] = {}
        self.graph_edges: list[tuple[str, str, str]] = []
        self.commit_order: list[str] = []
        self.snapshots: dict[str, dict[str, str]] = {}
        self.tree_snapshot_cache: dict[str, dict[str, str]] = {}
        self.path_changes: list[PathChange] = []
        self.lineage: list[LineageEdge] = []

        self.blob_text: dict[str, str] = {}
        self.detections: dict[str, list[Detection]] = {}
        self.secret_ids: dict[str, str] = {}
        self.family_ids: dict[str, str] = {}
        self.events: list[LifecycleEvent] = []
        self.occurrences: list[Occurrence] = []
        self.propagation: dict[str, list[dict[str, Any]]] = {}
        self.rules = build_rules()

        self.stats = Counter()
        if custom_rules:
            for rule in json.loads(custom_rules.read_text())["rules"]:
                score = float(rule.get("pattern_score", 0.95))
                if not math.isfinite(score) or not 0 <= score <= 1:
                    raise ValueError("Rule score must be within [0,1]")
                rx = re.compile(rule["regex"], re.M)
                group = int(rule.get("group", 0))
                if group < 0 or group > rx.groups:
                    raise ValueError("Invalid capture group in custom rule")
                self.rules.append(Rule(rule["name"], rx, score, group))

    # STEP 2 + STEP 4 foundations: complete object extraction and state.
    def extract_objects_and_states(self) -> None:
        fmt = "%(objectname) %(objecttype) %(objectsize)"
        cp = self.repo.run(["cat-file", "--batch-all-objects", f"--batch-check={fmt}"])
        for line in cp.stdout.decode("utf-8", errors="replace").splitlines():
            p = line.split()
            if len(p) != 3:
                continue
            try:
                self.objects[p[0]] = GitObject(p[0], p[1], int(p[2]))
            except ValueError:
                pass

        self.refs = self.repo.refs()
        self.head_oid = self.repo.head()
        self.reachable = self._rev_list("--all")
        if self.head_oid:
            self.reachable |= self._rev_list("HEAD")
        self.current = self._head_current_objects() if self.head_oid else set()
        self.packed = self._packed_objects()

        rev_refs: dict[str, list[str]] = defaultdict(list)
        for ref, oid in self.refs.items():
            rev_refs[oid].append(ref)

        for o in self.objects.values():
            o.reachable = o.oid in self.reachable
            o.current = o.oid in self.current
            o.historical = False  # Set from commit association, independently of reachability.
            o.unreachable = not o.reachable
            o.packed = o.oid in self.packed
            o.refs = sorted(rev_refs.get(o.oid, []))

    def _rev_list(self, rev: str) -> set[str]:
        cp = self.repo.run(["rev-list", "--objects", rev], check=False)
        if cp.returncode != 0:
            return set()
        return {line.split(" ", 1)[0] for line in cp.stdout.decode().splitlines() if line}

    def _head_current_objects(self) -> set[str]:
        """Objects representing the current HEAD snapshot, not all HEAD history."""
        if not self.head_oid:
            return set()
        out = {self.head_oid}
        cp_tree = self.repo.run(["rev-parse", "HEAD^{tree}"], check=False)
        if cp_tree.returncode == 0:
            tree_oid = cp_tree.stdout.decode().strip()
            if tree_oid:
                out.add(tree_oid)
        cp = self.repo.run(["ls-tree", "-r", "-t", "HEAD"], check=False)
        if cp.returncode == 0:
            for line in cp.stdout.decode("utf-8", errors="replace").splitlines():
                left = line.split("\t", 1)[0].split()
                if len(left) >= 3:
                    out.add(left[2])
        return out

    def _packed_objects(self) -> set[str]:
        found: set[str] = set()
        common = Path(self.repo.text(["rev-parse", "--git-common-dir"]).strip())
        if not common.is_absolute():
            common = (self.repo.path / common).resolve()
        packdir = common / "objects" / "pack"
        if not packdir.exists():
            return found
        oid_re = re.compile(r"^[0-9a-fA-F]{40,64}$")
        for idx in packdir.glob("*.idx"):
            cp = self.repo.run(["verify-pack", "-v", str(idx)], check=False)
            if cp.returncode != 0:
                continue
            for line in cp.stdout.decode("utf-8", errors="replace").splitlines():
                first = line.split(" ", 1)[0]
                if oid_re.fullmatch(first):
                    found.add(first.lower())
        return found

    # STEP 3: object graph.
    def build_graph(self) -> None:
        with BatchReader(self.repo) as br:
            for oid, obj in self.objects.items():
                if obj.obj_type not in {"commit", "tree", "tag"}:
                    continue
                try:
                    typ, data = br.read(oid)
                except GitError as exc:
                    self.warnings.append(str(exc))
                    continue
                self.stats["structural_objects_read"] += 1
                self.stats["structural_bytes_read"] += len(data)
                if typ == "commit":
                    self._parse_commit(oid, data)
                elif typ == "tree":
                    self._parse_tree(oid, data)
                elif typ == "tag":
                    self._parse_tag(oid, data)
        self._make_commit_order()

    def _parse_commit(self, oid: str, data: bytes) -> None:
        tree = None
        parents = []
        timestamp = 0
        for line in data.decode("utf-8", errors="replace").splitlines():
            if not line:
                break
            if line.startswith("tree "):
                tree = line[5:].strip()
            elif line.startswith("parent "):
                parents.append(line[7:].strip())
            elif line.startswith("author "):
                m = re.search(r"\s(\d+)\s[+-]\d{4}$", line)
                if m:
                    timestamp = int(m.group(1))
        self.commits[oid] = CommitInfo(oid, tree, parents, timestamp)
        if tree:
            self.graph_edges.append((oid, tree, "commit_tree"))
        self.graph_edges.extend((oid, p, "commit_parent") for p in parents)

    def _parse_tree(self, oid: str, data: bytes) -> None:
        out: list[TreeEntry] = []
        i = 0
        raw_oid = self.repo.raw_oid_len
        while i < len(data):
            sp = data.find(b" ", i)
            if sp < 0:
                break
            nul = data.find(b"\x00", sp + 1)
            if nul < 0:
                break
            mode = data[i:sp].decode("ascii", errors="replace")
            name = data[sp + 1:nul].decode("utf-8", errors="surrogateescape")
            end = nul + 1 + raw_oid
            if end > len(data):
                break
            child = data[nul + 1:end].hex()
            if mode == "160000":
                typ = "commit"
            elif mode.startswith("04") or mode == "40000":
                typ = "tree"
            else:
                typ = "blob"
            out.append(TreeEntry(mode, typ, child, name))
            self.graph_edges.append((oid, child, f"tree_{typ}"))
            i = end
        self.trees[oid] = out

    def _parse_tag(self, oid: str, data: bytes) -> None:
        for line in data.decode("utf-8", errors="replace").splitlines():
            if line.startswith("object "):
                target = line[7:].strip()
                self.tags[oid] = target
                self.graph_edges.append((oid, target, "tag_target"))
                return

    def _make_commit_order(self) -> None:
        # Kahn order over ALL local commits: timestamps never override ancestry.
        indegree = {oid: sum(p in self.commits for p in ci.parents) for oid, ci in self.commits.items()}
        children = defaultdict(list)
        for oid, ci in self.commits.items():
            for parent in ci.parents:
                if parent in self.commits:
                    children[parent].append(oid)
        queue = [(self.commits[o].timestamp, o) for o, n in indegree.items() if n == 0]
        heapq.heapify(queue)
        order = []
        while queue:
            _, oid = heapq.heappop(queue)
            order.append(oid)
            for child in children[oid]:
                indegree[child] -= 1
                if indegree[child] == 0:
                    heapq.heappush(queue, (self.commits[child].timestamp, child))
        if len(order) != len(self.commits):
            raise GitError("Cycle in commit graph")
        # Mark evidence independently from ref reachability, including unreachable history.
        historical = set()
        for oid in order:
            if oid == self.head_oid:
                continue
            historical.add(oid)
            tree = self.commits[oid].tree
            stack = [tree] if tree else []
            while stack:
                node = stack.pop()
                if node in historical:
                    continue
                historical.add(node)
                for entry in self.trees.get(node, []):
                    if entry.obj_type == "tree":
                        stack.append(entry.oid)
                    elif entry.obj_type == "blob":
                        historical.add(entry.oid)
        for oid in historical:
            if oid in self.objects:
                self.objects[oid].historical = True
        self.commit_order = order[-self.max_commits:] if self.max_commits else order
        if len(self.commit_order) < len(order):
            self.warnings.append("Commit limit truncates ancestry; boundary events are observations, not proven introductions.")


    def build_snapshots(self) -> None:
        for commit in self.commit_order:
            ci = self.commits.get(commit)
            if ci and ci.tree:
                self.snapshots[commit] = self._snapshot_tree(ci.tree)

        for commit in self.commit_order:
            ci = self.commits.get(commit)
            if not ci:
                continue
            new = self.snapshots.get(commit, {})
            parents = [p for p in ci.parents if p in self.snapshots]
            if not parents:
                for path, blob in new.items():
                    self.path_changes.append(PathChange(None, commit, ci.timestamp, path, None, blob, "introduced"))
                continue
            for parent in parents:
                self._diff_snapshots(parent, commit, self.snapshots[parent], new)

    def _snapshot_tree(self, tree: str) -> dict[str, str]:
        if tree not in self.trees:
            raise GitError(f"Missing tree {tree}; refusing to infer absence from incomplete snapshots")
        if tree in self.tree_snapshot_cache:
            return self.tree_snapshot_cache[tree]
        result: dict[str, str] = {}
        def walk(t: str, prefix: str) -> None:
            if t not in self.trees:
                raise GitError(f"Missing subtree {t}; lifecycle cannot be reconstructed reliably")
            for e in self.trees[t]:
                path = f"{prefix}/{e.name}" if prefix else e.name
                if e.obj_type == "blob":
                    result[path] = e.oid
                elif e.obj_type == "tree":
                    walk(e.oid, path)
        walk(tree, "")
        self.tree_snapshot_cache[tree] = dict(result)
        return result

    def _diff_snapshots(self, parent: str, commit: str, old: dict[str, str], new: dict[str, str]) -> None:
        ts = self.commits[commit].timestamp
        for path in sorted(set(old) | set(new)):
            a, b = old.get(path), new.get(path)
            if a == b:
                continue
            event = "deleted" if a and not b else "added" if b and not a else "modified"
            self.path_changes.append(PathChange(parent, commit, ts, path, a, b, event))


    def infer_lineage(self) -> None:
        # No hidden pre-budget reads: similarity only uses content already examined by detect().
        def edge(parent, commit, sp, tp, a, b):
            if a != b and (a not in self.blob_text or b not in self.blob_text):
                return None
            if a == b:
                content = 1.0
            else:
                aa, bb = self.blob_text[a], self.blob_text[b]
                if not aa or not bb:
                    return None
                content = SequenceMatcher(None, aa[:200000], bb[:200000], autojunk=True).ratio()
            path = 1.0 if sp == tp else (0.65 * SequenceMatcher(None, Path(sp).name, Path(tp).name).ratio() + 0.35 * SequenceMatcher(None, str(Path(sp).parent), str(Path(tp).parent)).ratio())
            days = max(0, self.commits[commit].timestamp - self.commits[parent].timestamp) / 86400
            temporal = math.exp(-days / 90)
            confidence = sum(self.lineage_weights[k] * v for k, v in {"content": content, "path": path, "commit": 1.0, "temporal": temporal}.items())
            if a == b:
                confidence = 1.0
            if confidence < self.lineage_threshold or (sp != tp and content < 0.65):
                return None
            return LineageEdge(a, b, sp, tp, parent, commit, content, path, 1.0, temporal, round(confidence, 6))

        for commit in self.commit_order:
            ci = self.commits[commit]
            new = self.snapshots.get(commit, {})
            for parent in ci.parents:
                if parent not in self.snapshots:
                    continue
                old = self.snapshots[parent]
                for path in sorted(set(old) & set(new)):
                    if old[path] != new[path]:
                        e = edge(parent, commit, path, path, old[path], new[path])
                        if e:
                            self.lineage.append(e)
                for tp in sorted(set(new) - set(old)):
                    exact = [sp for sp in old if old[sp] == new[tp]]
                    if exact:
                        sources = sorted(exact)
                    else:
                        sources = sorted(old, key=lambda sp: (sp in new, -SequenceMatcher(None, Path(sp).name, Path(tp).name).ratio(), sp))
                    if len(sources) > self.max_lineage_candidates:
                        self.stats["lineage_candidate_paths_skipped"] += len(sources) - self.max_lineage_candidates
                    candidates = []
                    for sp in sources[:self.max_lineage_candidates]:
                        e = edge(parent, commit, sp, tp, old[sp], new[tp])
                        if e:
                            candidates.append(e)
                    candidates.sort(key=lambda e: (-e.confidence, e.source_path))
                    if candidates and (len(candidates) == 1 or candidates[0].confidence - candidates[1].confidence >= 0.05):
                        self.lineage.append(candidates[0])
                    elif candidates:
                        self.uncertain_transitions.append({"commit": commit, "parent": parent, "path": tp, "reason": "ambiguous_lineage_source", "candidates": [asdict(e) for e in candidates]})


    def _load_blob_text(self, ids: Iterable[str]) -> None:
        # Backward compatible method; detect() owns content reads and accounting.
        return None


    def detect(self) -> None:
        blobs = [o.oid for o in self.objects.values() if o.obj_type == "blob"]
        for oid in blobs:
            self.scan_status[oid] = "out_of_scope" if not self._in_scope(self.objects[oid]) else "budget_excluded"
        selected = [oid for oid in blobs if self._in_scope(self.objects[oid])]
        selected.sort(key=lambda oid: (-self._pre_priority(self.objects[oid]), oid))
        if self.object_budget:
            selected = selected[:self.object_budget]
        with BatchReader(self.repo) as br:
            for i, oid in enumerate(selected, 1):
                obj = self.objects[oid]
                if obj.size > self.max_blob_size:
                    self.scan_status[oid] = "size_excluded"
                    self.stats["skipped_large_blobs"] += 1
                    continue
                try:
                    typ, raw = br.read(oid)
                except GitError as exc:
                    self.scan_status[oid] = "read_error"
                    self.warnings.append(str(exc))
                    continue
                self.stats["objects_scanned"] += 1
                self.stats["bytes_scanned"] += len(raw)
                self.stats["blob_reads_total"] += 1
                self.stats["blob_bytes_read_total"] += len(raw)
                binary = self._binary(raw)
                if binary:
                    self.stats["binary_blobs"] += 1
                if binary and not self.include_binary_strings:
                    self.scan_status[oid] = "binary_excluded"
                    continue
                pieces = self._content_parts(raw)
                self.scan_status[oid] = "scanned_binary_partial" if binary or raw.startswith((b"PK", b"\x1f\x8b")) else "scanned_text"
                ds = []
                texts = []
                for artifact, text, partial in pieces:
                    texts.append(text)
                    for detection in self._detect_text(text, partial):
                        detection.artifact = artifact
                        ds.append(detection)
                self.blob_text[oid] = "\n".join(texts)[:200000]
                self.detections[oid] = ds
                self.stats["accepted_matches"] += len(ds)
                self._progress(f"Detecting blobs {i}/{len(selected)}; matches={self.stats['accepted_matches']}")


    def _in_scope(self, o: GitObject) -> bool:
        return self.scope == "all" or (self.scope == "current" and o.current) or (self.scope == "reachable" and o.reachable) or (self.scope == "unreachable" and o.unreachable)

    @staticmethod
    def _pre_priority(o: GitObject) -> float:
        return (1.0 if o.current else 0.82 if o.reachable else 0.45) + (0.20 if o.historical else 0.0)

    @staticmethod
    def _binary(raw: bytes) -> bool:
        if not raw:
            return False
        s = raw[:8192]
        if b"\x00" in s:
            return True
        odd = sum(1 for b in s if b < 9 or 13 < b < 32 or b == 127)
        return odd / max(1, len(s)) > 0.15

    @staticmethod
    def _printable(raw: bytes) -> str:
        return "\n".join(m.group().decode("ascii", errors="ignore") for m in re.finditer(rb"[\x20-\x7e]{8,}", raw))

    def _detect_text(self, text: str, binary_extracted: bool) -> list[Detection]:
        out: dict[str, Detection] = {}
        for rule in self.rules:
            for m in rule.regex.finditer(text):
                try:
                    value = m.group(rule.group)
                    start, _ = m.span(rule.group)
                except IndexError:
                    value, start = m.group(0), m.start()
                norm = normalize_secret(value)
                if len(norm) < 8:
                    continue
                window = text[max(0, start - 160): min(len(text), m.end() + 160)].lower()
                positive = sum(1 for k in POSITIVE_CONTEXT if k in window)
                negative = sum(1 for k in NEGATIVE_CONTEXT if k in window)
                cscore = clamp01(0.45 + min(0.45, positive * 0.12) - min(0.45, negative * 0.15) + (0.08 if len(norm) >= 20 and shannon_entropy(norm) >= 3.5 else 0.0))
                escore = entropy_score(norm)
                confidence = (
                    self.content_weights["pattern"] * rule.pattern_score +
                    self.content_weights["entropy"] * escore +
                    self.content_weights["context"] * cscore
                )
                line = text.count("\n", 0, start) + 1
                last = text.rfind("\n", 0, start)
                column = start + 1 if last < 0 else start - last
                d = Detection(rule.name, value, norm, fingerprint(norm), line, column, round(rule.pattern_score, 6), round(escore, 6), round(cscore, 6), round(clamp01(confidence), 6), binary_extracted)
                prefix = text[max(0, text.rfind("\n", 0, start) + 1):start]
                assigned = re.search(r"([A-Za-z_][A-Za-z0-9_.-]*)[\"\']?\s*[:=]\s*[\"\']?$", prefix)
                d.context_key = assigned.group(1).lower() if assigned else ""
                if d.content_confidence < self.min_confidence:
                    self.stats["rejected_candidates"] += 1
                    continue
                key = (d.fingerprint, d.line, d.column)
                if key not in out or d.content_confidence > out[key].content_confidence:
                    out[key] = d
        return sorted(out.values(), key=lambda d: (d.line, d.column, d.detector))

    # STEP 7: exact identity + modified/rotated family correlation.
    def correlate(self) -> None:
        all_dets = [d for ds in self.detections.values() for d in ds]
        counters = Counter()
        for d in sorted(all_dets, key=lambda d: (d.fingerprint, d.detector)):
            if d.fingerprint not in self.secret_ids:
                counters[d.detector] += 1
                self.secret_ids[d.fingerprint] = f"S-{d.fingerprint[:20]}"

        parent = {fp: fp for fp in self.secret_ids}
        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        for edge in self.lineage:
            for a in self.detections.get(edge.source_blob, []):
                for b in self.detections.get(edge.target_blob, []):
                    if (a.detector != b.detector or a.fingerprint == b.fingerprint
                            or not a.context_key or a.context_key != b.context_key):
                        continue
                    sim = SequenceMatcher(None, a.normalized, b.normalized, autojunk=False).ratio()
                    if sim >= self.rotation_threshold:
                        union(a.fingerprint, b.fingerprint)

        root_to_family: dict[str, str] = {}
        n = 0
        for fp in self.secret_ids:
            root = find(fp)
            if root not in root_to_family:
                n += 1
                root_to_family[root] = f"F-{n:04d}"
            self.family_ids[fp] = root_to_family[root]

    # STEP 8: lifecycle construction.
    def build_lifecycle(self) -> None:
        def values(blob):
            return {d.fingerprint: d for d in self.detections.get(blob or "", [])}
        def examined(blob):
            return blob is None or self.scan_status.get(blob) == "scanned_text"
        def event(fp, kind, commit, path, blob, parent=None, related=None, details="", confidence=1.0, status="observed"):
            self.events.append(LifecycleEvent(self.secret_ids[fp], kind, commit, self.commits[commit].timestamp, path, blob, details, confidence, parent, related, status))
        # Occurrence context differs from the global blob state.
        for commit in self.commit_order:
            ci = self.commits[commit]
            for path, blob in sorted(self.snapshots.get(commit, {}).items()):
                obj = self.objects.get(blob)
                if not obj:
                    continue
                for fp, d in values(blob).items():
                    self.occurrences.append(Occurrence(self.secret_ids[fp], self.family_ids[fp], d.detector, fp, blob, path, commit, ci.timestamp, commit == self.head_oid, obj.reachable, commit != self.head_oid, obj.packed, d.content_confidence, evidence=["Current/historical labels describe this commit occurrence; reachability/storage describe its blob."]))
        known = {o.blob_oid for o in self.occurrences}
        for blob, ds in self.detections.items():
            if blob in known:
                continue
            obj = self.objects[blob]
            for fp, d in values(blob).items():
                self.occurrences.append(Occurrence(self.secret_ids[fp], self.family_ids[fp], d.detector, fp, blob, "<unknown>", None, None, obj.current, obj.reachable, obj.historical, obj.packed, d.content_confidence, evidence=["No reconstructed path/commit; chronology is unknown."]))

        # Parent-specific lineage prevents branch timestamps from inventing transitions.
        inferred = {(e.source_commit, e.target_commit, e.target_path): e for e in self.lineage if e.source_path != e.target_path}
        history = {}  # commit -> path -> fp -> last known secret-bearing blob
        for commit in self.commit_order:
            ci = self.commits[commit]
            new = self.snapshots.get(commit, {})
            carried = defaultdict(dict)
            parents = ci.parents or [None]
            for parent in parents:
                boundary = parent is not None and parent not in self.snapshots
                old = self.snapshots.get(parent, {})
                prior = history.get(parent, {})
                moved = {e.source_path: e.target_path for (p, c, _), e in inferred.items() if p == parent and c == commit and e.source_path not in new}
                for path in sorted(set(old) | set(new)):
                    a, b = old.get(path), new.get(path)
                    edge = inferred.get((parent, commit, path))
                    source_path = edge.source_path if edge else path
                    if edge:
                        a = old.get(source_path)
                    before, after = values(a), values(b)
                    past = dict(prior.get(source_path, {}))
                    for fp in before:
                        past[fp] = a
                    if b:
                        carried[path].update(past)
                        for fp in after:
                            carried[path][fp] = b
                    if path in moved and b is None:
                        continue  # A rename is not a deletion of the tracked file identity.
                    if a == b and b and not edge:
                        for fp in after:
                            event(fp, "persistence", commit, path, b, parent, details="Same accepted secret in unchanged content.")
                        continue
                    for fp in after:
                        if fp in before:
                            kind = ("renamed" if source_path not in new else "copied") if edge else "persistence"
                            event(fp, kind, commit, path, b, parent, source_path if edge else None, "Parent-child content evidence; transfer source is inferred." if edge else "Identical credential persists.", edge.confidence if edge else 1.0, "inferred" if edge else "observed")
                        elif boundary or not examined(a):
                            event(fp, "first_observed", commit, path, b, parent, details="Predecessor unavailable or not fully text-scanned; introduction unproven.", status="incomplete")
                        else:
                            event(fp, "introduction", commit, path, b, parent, details="Accepted candidate absent from examined predecessor at this path.")
                    for fp in before.keys() - after.keys():
                        if b is None:
                            event(fp, "file_deleted", commit, path, a, parent, details="Secret-bearing file removed from this parent-child transition.")
                        elif examined(b):
                            event(fp, "secret_removed", commit, path, a, parent, details="No matching accepted credential in examined successor text.")
                        else:
                            self.uncertain_transitions.append({"secret_id": self.secret_ids[fp], "parent": parent, "commit": commit, "path": path, "reason": "successor_not_fully_examined", "scan_status": self.scan_status.get(b, "unknown")})
                    if b is None:
                        for fp, secret_blob in past.items():
                            if fp not in before:
                                event(fp, "file_deleted_after_removal", commit, path, secret_blob, parent, details="Previously tracked credential removed earlier; associated file now deleted.")
                    for fp, da in before.items():
                        for gp, db in after.items():
                            if fp == gp or not da.context_key or da.context_key != db.context_key or da.detector != db.detector:
                                continue
                            similarity = SequenceMatcher(None, da.normalized, db.normalized, autojunk=False).ratio()
                            # Replacement is a contextual observation, never proof of revocation/rotation.
                            event(fp, "possible_credential_replacement", commit, path, b, parent, details=f"Same assignment key; successor={self.secret_ids[gp]}; similarity={similarity:.3f}. Credential rotation/validity unverified.", confidence=0.75, status="inferred")
            history[commit] = dict(carried)
        # Deduplicate per parent, preserving distinct merge-parent evidence.
        unique = {}
        for e in self.events:
            unique[(e.secret_id, e.event, e.parent_commit, e.commit, e.path, e.blob_oid, e.related_path)] = e
        self.events = list(unique.values())
        for e in self.events:
            if e.event in {"file_deleted", "file_deleted_after_removal", "secret_removed"} and e.blob_oid in self.objects:
                obj = self.objects[e.blob_oid]
                e.details += f" Retained locally: reachable={obj.reachable}, packed={obj.packed}."


    def analyze_propagation(self) -> None:
        by_sid = defaultdict(list)
        for occurrence in self.occurrences:
            by_sid[occurrence.secret_id].append(occurrence)
        for sid, occurrences in by_sid.items():
            self.propagation[sid] = [{"commit": o.commit, "path": o.path, "blob_oid": o.blob_oid, "timestamp": o.timestamp, "reachable": o.reachable} for o in occurrences]
        for e in self.events:
            if e.event in {"copied", "renamed"}:
                self.propagation_edges.append({"secret_id": e.secret_id, "source_commit": e.parent_commit, "target_commit": e.commit, "source_path": e.related_path, "target_path": e.path, "kind": e.event, "confidence": e.confidence, "evidence": "Exact secret identity plus parent-child inferred file lineage; not proof of a human copy action."})
        # Cross-path secret copies may occur into existing files, without file-level lineage.
        existing = {(e["secret_id"], e["source_commit"], e["target_commit"], e["target_path"]) for e in self.propagation_edges}
        for e in self.events:
            if e.event != "introduction" or e.parent_commit not in self.snapshots:
                continue
            sources = set()
            for path, blob in self.snapshots[e.parent_commit].items():
                if path != e.path and any(self.secret_ids[d.fingerprint] == e.secret_id for d in self.detections.get(blob, [])):
                    sources.add(path)
            key = (e.secret_id, e.parent_commit, e.commit, e.path)
            if key in existing:
                continue
            if len(sources) == 1:
                self.propagation_edges.append({"secret_id": e.secret_id, "source_commit": e.parent_commit, "target_commit": e.commit, "source_path": next(iter(sources)), "target_path": e.path, "kind": "possible_copy", "confidence": 0.8, "evidence": "Exact identity at a unique predecessor location; transfer inferred, not proven."})
            elif sources:
                self.uncertain_transitions.append({"secret_id": e.secret_id, "commit": e.commit, "path": e.path, "reason": "ambiguous_secret_copy_source", "source_paths": sorted(sources)})

    def score(self) -> None:
        lineage_by_blob = defaultdict(float)
        for e in self.lineage:
            lineage_by_blob[e.source_blob] = max(lineage_by_blob[e.source_blob], e.confidence)
            lineage_by_blob[e.target_blob] = max(lineage_by_blob[e.target_blob], e.confidence)

        events_by_sid: dict[str, list[LifecycleEvent]] = defaultdict(list)
        for e in self.events:
            events_by_sid[e.secret_id].append(e)
        locations: dict[str, set[str]] = defaultdict(set)
        times: dict[str, list[int]] = defaultdict(list)
        for o in self.occurrences:
            if o.path != "<unknown>":
                locations[o.secret_id].add(o.path)
            if o.timestamp is not None:
                times[o.secret_id].append(o.timestamp)

        ancestry_cache = {}
        def ancestor(older, newer):
            if older is None or newer is None:
                return False
            pair = (older, newer)
            if pair not in ancestry_cache:
                stack, seen = [newer], set()
                while stack:
                    commit = stack.pop()
                    if commit in seen:
                        continue
                    seen.add(commit)
                    stack.extend(self.commits[commit].parents if commit in self.commits else [])
                ancestry_cache[pair] = older in seen
            return ancestry_cache[pair]

        for o in self.occurrences:
            if o.current:
                r = 1.0
                o.evidence.append("Secret-bearing object is part of current HEAD state.")
            elif o.reachable:
                r = 0.82
                o.evidence.append("Secret-bearing object is reachable from refs/history.")
            else:
                r = 0.45
                o.evidence.append("Secret-bearing object is unreachable but still physically present locally.")

            d = 0.0
            for e in events_by_sid[o.secret_id]:
                if ancestor(o.commit, e.commit) and (e.blob_oid == o.blob_oid or e.path == o.path):
                    if e.event in {"file_deleted", "file_deleted_after_removal"}:
                        d = max(d, 1.0)
                    elif e.event == "secret_removed":
                        d = max(d, 0.90)
                    elif e.event == "possible_credential_replacement":
                        d = max(d, 0.65)
            if d:
                o.evidence.append(f"Deletion/removal evidence={d:.2f}.")

            t = times[o.secret_id]
            life_days = (max(t) - min(t)) / 86400.0 if len(t) >= 2 else 0.0
            life = 1.0 - math.exp(-life_days / 30.0)
            h = clamp01(0.65 * (0.75 if o.historical else 0.25) + 0.35 * life)
            l = clamp01(lineage_by_blob[o.blob_oid])
            nloc = len(locations[o.secret_id])
            p = clamp01(1.0 - math.exp(-max(0, nloc - 1) / 3.0))
            if nloc > 1:
                o.evidence.append(f"Same exact secret appears across {nloc} locations.")

            o.reachability_score = round(r, 6)
            o.deletion_score = round(d, 6)
            o.historical_score = round(h, 6)
            o.lineage_score = round(l, 6)
            o.propagation_score = round(p, 6)
            components = {"content": o.content_confidence, "reachability": r, "deletion": d, "historical": h, "lineage": l, "propagation": p}
            active = {"A": {"content"}, "B": {"content", "reachability", "historical"}, "C": {"content", "reachability", "historical", "lineage"}, "D": {"content", "reachability", "historical", "lineage", "propagation"}, "E": set(components)}[self.model]
            denom = sum(self.risk_weights[k] for k in active)
            if denom <= 0:
                raise ValueError("Active model weights must have a positive sum")
            risk = sum(self.risk_weights[k] * components[k] for k in active) / denom
            o.final_risk = round(clamp01(risk), 6)
            o.risk_class = risk_class(o.final_risk)

        self.occurrences.sort(key=lambda x: (-x.final_risk, x.fingerprint, x.path, x.commit or ""))

    # STEP 12: optional controlled ground-truth evaluation.
    def evaluate(self, manifest: Path | None) -> dict[str, Any] | None:
        if manifest is None:
            return None
        report = self.report(str(self.repo.path), [], now_iso(), 0, False, None)
        return evaluate_report(report, json.loads(manifest.read_text(encoding="utf-8")))

    def _content_parts(self, raw: bytes) -> list[tuple[str, str, bool]]:
        # Bounded, in-memory extraction. No archive paths are written to disk.
        out = []
        remaining = self.max_blob_size
        members = 0
        def unpack(data, name, depth):
            nonlocal remaining, members
            if depth < 2 and data.startswith(b"PK\x03\x04"):
                try:
                    with zipfile.ZipFile(io.BytesIO(data)) as z:
                        for entry in z.infolist():
                            if entry.is_dir():
                                continue
                            members += 1
                            if members > 100 or entry.file_size > remaining:
                                self.stats["archive_members_skipped"] += 1
                                continue
                            with z.open(entry) as f:
                                value = f.read(remaining + 1)
                            if len(value) > remaining:
                                self.stats["archive_members_skipped"] += 1
                                continue
                            remaining -= len(value)
                            self.stats["archive_bytes_expanded"] += len(value)
                            unpack(value, name + "!" + entry.filename, depth + 1)
                    return
                except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError):
                    self.stats["archive_errors"] += 1
            elif depth < 2 and data.startswith(b"\x1f\x8b"):
                try:
                    with gzip.GzipFile(fileobj=io.BytesIO(data)) as f:
                        value = f.read(remaining + 1)
                    if len(value) > remaining:
                        self.stats["archive_members_skipped"] += 1
                        return
                    remaining -= len(value)
                    self.stats["archive_bytes_expanded"] += len(value)
                    unpack(value, name + "!gzip", depth + 1)
                    return
                except (OSError, EOFError, ValueError):
                    self.stats["archive_errors"] += 1
            binary = self._binary(data)
            out.append((name, self._printable(data) if binary else data.decode("utf-8", errors="replace"), binary or depth > 0))
        unpack(raw, "blob", 0)
        return out


    def _progress(self, message: str, force: bool = False) -> None:
        t = time.monotonic()
        if self.progress and (force or t - self._last_progress >= 0.25):
            print(f"[{NAME}] {message}", file=sys.stderr, flush=True)
            self._last_progress = t


    def report(self, target: str, notes: list[str], started_at: str, duration: float, show: bool, evaluation: dict[str, Any] | None) -> dict[str, Any]:
        type_counts = Counter(o.obj_type for o in self.objects.values())
        state_counts = {
            "reachable": sum(o.reachable for o in self.objects.values()),
            "unreachable": sum(o.unreachable for o in self.objects.values()),
            "current": sum(o.current for o in self.objects.values()),
            "historical": sum(o.historical for o in self.objects.values()),
            "packed": sum(o.packed for o in self.objects.values()),
        }
        detections = []
        for blob, ds in self.detections.items():
            for d in ds:
                row = asdict(d)
                row["blob_oid"] = blob
                row["value"] = redact(d.value, show)
                row["normalized"] = redact(d.normalized, show)
                detections.append(row)

        secret_summary = []
        order_index = {oid: i for i, oid in enumerate(self.commit_order)}
        occ_by_sid: dict[str, list[Occurrence]] = defaultdict(list)
        ev_by_sid: dict[str, list[LifecycleEvent]] = defaultdict(list)
        for o in self.occurrences:
            occ_by_sid[o.secret_id].append(o)
        for e in self.events:
            ev_by_sid[e.secret_id].append(e)
        fp_to_det = {d.fingerprint: d for ds in self.detections.values() for d in ds}
        for fp, sid in sorted(self.secret_ids.items(), key=lambda x: x[1]):
            dsample = fp_to_det[fp]
            occs = occ_by_sid.get(sid, [])
            ts = [o.timestamp for o in occs if o.timestamp is not None]
            secret_summary.append({
                "secret_id": sid,
                "family_id": self.family_ids[fp],
                "detector": dsample.detector,
                "fingerprint": fp,
                "secret_value": redact(dsample.normalized, show),
                "first_observed": min(ts) if ts else None,
                "last_observed": max(ts) if ts else None,
                "distinct_paths": sorted({o.path for o in occs}),
                "distinct_blobs": sorted({o.blob_oid for o in occs}),
                "lifecycle": [asdict(e) for e in sorted(ev_by_sid.get(sid, []), key=lambda x: (order_index.get(x.commit, -1), x.parent_commit or "", x.event))],
                "propagation_chain": self.propagation.get(sid, []),
                "observation_note": "Commit timestamps are observations, not credential issue/expiry times; event order follows ancestry.",
                "persistence_blob_count": len({o.blob_oid for o in occs}),
                "observed_commit_count": len({o.commit for o in occs if o.commit}),
            })

        return {
            "schema": "gasld-report-v2",
            "model": self.model,
            "score_interpretation": "Experimental exposure-priority score; not a compromise probability or credential-validity assessment.",
            "warnings": self.warnings,
            "coverage": {"scan_status_counts": dict(Counter(self.scan_status.values())), "blob_status": self.scan_status, "complete_text_scan": all(v == "scanned_text" for v in self.scan_status.values()), "reachability_roots": "all refs plus HEAD; reflogs excluded", "historical_definition": "association with a parsed non-HEAD commit", "current_definition": "committed HEAD snapshot; uncommitted working files excluded", "absence_meaning": "no matching accepted candidate under the configured detector", "max_blob_size": self.max_blob_size, "object_budget": self.object_budget, "max_commits": self.max_commits, "lineage_candidate_limit": self.max_lineage_candidates},
            "git_state_snapshot": {oid: {"type": o.obj_type, "reachable": o.reachable, "historical": o.historical, "packed": o.packed} for oid, o in self.objects.items()},
            "uncertain_transitions": self.uncertain_transitions,
            "propagation_edges": self.propagation_edges,
            "phase_seconds": self.phase_seconds,
            "peak_python_memory_bytes": self.peak_memory_bytes,
            "io_accounting": dict(self.stats),
            "scanner": NAME,
            "version": VERSION,
            "started_at": started_at,
            "duration_seconds": round(duration, 6),
            "target": target,
            "repository_path": str(self.repo.path),
            "notes": notes,
            "scope": self.scope,
            "experimental_parameters": {
                "min_content_confidence": self.min_confidence,
                "fingerprint_normalization": "v2 exact extracted value; PEM CRLF normalized; spaces preserved",
                "content_weights": self.content_weights,
                "lineage_weights": self.lineage_weights,
                "lineage_threshold": self.lineage_threshold,
                "rotation_threshold": self.rotation_threshold,
                "risk_weights": self.risk_weights,
                "risk_thresholds": RISK_THRESHOLDS_DEFAULT,
                "warning": "Weights and thresholds are experimental parameters, not scientifically established constants."
            },
            "repository": {
                "head": self.head_oid,
                "object_format": self.repo.object_format,
                "refs": self.refs,
                "object_counts": dict(type_counts),
                "state_counts": state_counts,
                "graph_edge_count": len(self.graph_edges),
                "commits_analyzed": len(self.commit_order),
                "path_change_count": len(self.path_changes),
            },
            "statistics": {
                "objects_scanned": self.stats["objects_scanned"],
                "bytes_scanned": self.stats["bytes_scanned"],
                "bytes_scanned_human": human_bytes(self.stats["bytes_scanned"]),
                "binary_blobs": self.stats["binary_blobs"],
                "skipped_large_blobs": self.stats["skipped_large_blobs"],
                "lineage_edges": len(self.lineage),
                "unique_secrets": len(self.secret_ids),
                "occurrences": len(self.occurrences),
                "lifecycle_events": len(self.events),
            },
            "lineage_edges": [asdict(x) for x in self.lineage],
            "secret_detections": detections,
            "secret_identities": secret_summary,
            "prioritized_findings": [asdict(x) for x in self.occurrences],
            "ground_truth_evaluation": evaluation,
            "secrets_redacted": not show,
        }


def compare_snapshots(previous: dict, current: dict) -> dict:
    if previous.get("repository_path") != current.get("repository_path"):
        raise ValueError("Snapshot comparison requires the same local repository path")
    if previous.get("schema") != "gasld-report-v2" or "git_state_snapshot" not in previous:
        raise ValueError("Previous report needs v2 git_state_snapshot evidence")
    old_refs, new_refs = previous["repository"]["refs"], current["repository"]["refs"]
    old, new = previous["git_state_snapshot"], current["git_state_snapshot"]
    return {
        "previous_started_at": previous["started_at"], "current_started_at": current["started_at"],
        "removed_refs": [{"ref": ref, "previous_tip": old_refs[ref]} for ref in sorted(set(old_refs) - set(new_refs))],
        "added_refs": [{"ref": ref, "tip": new_refs[ref]} for ref in sorted(set(new_refs) - set(old_refs))],
        "moved_refs": [{"ref": ref, "previous_tip": old_refs[ref], "current_tip": new_refs[ref]} for ref in sorted(set(old_refs) & set(new_refs)) if old_refs[ref] != new_refs[ref]],
        "became_unreachable": sorted(oid for oid in set(old) & set(new) if old[oid]["reachable"] and not new[oid]["reachable"]),
        "no_longer_enumerated": sorted(set(old) - set(new)),
        "evidence_note": "Observed differences between two scans. Ref movement is not proof of commit deletion; missing objects do not prove garbage collection or credential revocation. Reports should describe the same repository identity, not just a reused path."
    }


def classification_metrics(tp: int, fp: int, fn: int) -> dict[str, Any]:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return {"tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}


def validate_manifest(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    if not isinstance(data.get("items"), list):
        raise ValueError("Ground truth requires items list")
    labels = {}
    for item in data["items"]:
        if "expected_secret" in item and not isinstance(item["expected_secret"], bool):
            raise ValueError("expected_secret must be boolean")
        fp = item.get("fingerprint") or (fingerprint(str(item["value"])) if "value" in item else None)
        if not fp or not re.fullmatch(r"[0-9a-f]{64}", fp):
            raise ValueError("Ground truth needs a full SHA256 fingerprint or exact extracted value")
        if fp in labels:
            raise ValueError("Duplicate ground-truth credential; use occurrences for multiple locations")
        if "relevance" in item and (isinstance(item["relevance"], bool) or not isinstance(item["relevance"], (int, float)) or not math.isfinite(item["relevance"]) or not 0 <= item["relevance"] <= 4):
            raise ValueError("relevance must be a finite graded label in [0,4]")
        labels[fp] = item
    if data.get("unlisted_policy", "unjudged") not in {"unjudged", "negative"}:
        raise ValueError("unlisted_policy must be unjudged or negative")
    if data.get("unlisted_policy") == "negative" and data.get("complete") is not True:
        raise ValueError("Closed-world negatives require complete=true independently verified ground truth")
    return labels


def ranking_metrics(ranked: list[str], labels: dict[str, dict[str, Any]], ks=(1, 5, 10)) -> dict[str, Any]:
    grades = {fp: float(row["relevance"]) for fp, row in labels.items() if "relevance" in row}
    positives = sum(g > 0 for g in grades.values())
    ideal = sorted(grades.values(), reverse=True)
    results = {}
    for k in ks:
        top = ranked[:k]
        unjudged = sum(fp not in grades for fp in top)
        relevant = sum(grades.get(fp, 0) > 0 for fp in top)
        denom = k  # Missing results count as empty ranks, explicitly fixed-K.
        dcg = sum((2 ** grades.get(fp, 0) - 1) / math.log2(i + 2) for i, fp in enumerate(top))
        idcg = sum((2 ** g - 1) / math.log2(i + 2) for i, g in enumerate(ideal[:k]))
        results[str(k)] = {"returned": len(top), "unjudged": unjudged,
            "precision_at_k": relevant / denom if not unjudged else None,
            "recall_at_k": relevant / positives if positives and not unjudged else None,
            "ndcg_at_k": dcg / idcg if idcg and not unjudged else None,
            "precision_lower_bound": relevant / denom,
            "precision_upper_bound": (relevant + unjudged) / denom}
    return {"unit": "unique secret fingerprint, max occurrence score; fixed K denominator", "known_relevant": positives, "metrics": results}


def structured_metrics(predictions: list[dict], expected: list[dict], required: tuple[str, ...], complete: bool) -> dict:
    # Exact schema projection. Expected rows must specify every matching field.
    def key(row):
        if any(k not in row for k in required):
            raise ValueError("Structured ground truth requires: " + ", ".join(required))
        return tuple(row[k] for k in required)
    truth = {key(row) for row in expected}
    predicted = {key(row) for row in predictions}
    tp = len(truth & predicted)
    unmatched = len(predicted - truth)
    result = classification_metrics(tp, unmatched if complete else 0, len(truth - predicted))
    result.update({"matching_fields": required, "complete_labels": complete, "unjudged_predictions": 0 if complete else unmatched})
    if unmatched and not complete:
        result["precision"] = result["f1"] = None
    return result


def evaluate_report(report: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    labels = validate_manifest(data)
    found = {d["fingerprint"] for d in report["secret_detections"]}
    positives = {fp for fp, row in labels.items() if row.get("expected_secret", True)}
    negatives = set(labels) - positives
    extra = found - set(labels)
    closed = data.get("unlisted_policy") == "negative"
    tp, fp, fn = len(found & positives), len(found & negatives) + (len(extra) if closed else 0), len(positives - found)
    result = classification_metrics(tp, fp, fn)
    result.update({"tn": len(negatives - found), "unit": "unique credential fingerprint", "labelled_subset_precision": result["precision"], "unjudged_detections": sorted(extra) if not closed else [], "missing_known_secrets": sorted(positives - found), "unlisted_policy": data.get("unlisted_policy", "unjudged"), "ground_truth_complete": data.get("complete", False)})
    if extra and not closed:
        result["precision"] = result["f1"] = None
    result["precision_lower_bound"] = tp / len(found) if found else None
    result["precision_upper_bound"] = (tp + (len(extra) if not closed else 0)) / len(found) if found else None
    ranked = []
    for o in report["prioritized_findings"]:
        if o["fingerprint"] not in ranked:
            ranked.append(o["fingerprint"])
    result["ranking"] = ranking_metrics(ranked, labels)
    by_id = {s["secret_id"]: s["fingerprint"] for s in report["secret_identities"]}
    specifications = [
        ("events", [{**e, "fingerprint": by_id[e["secret_id"]]} for s in report["secret_identities"] for e in s["lifecycle"]], ("fingerprint", "event", "commit", "parent_commit", "path")),
        ("lineage", report["lineage_edges"], ("source_blob", "target_blob", "source_commit", "target_commit", "source_path", "target_path")),
        ("propagation", [{**e, "fingerprint": by_id[e["secret_id"]]} for e in report.get("propagation_edges", [])], ("fingerprint", "source_commit", "target_commit", "source_path", "target_path", "kind")),
        ("occurrences", report["prioritized_findings"], ("fingerprint", "blob_oid", "commit", "path")),
    ]
    for name, predictions, fields in specifications:
        if name in data:
            result[name] = structured_metrics(predictions, data[name], fields, data.get(name + "_complete") is True)
    if "identity_pairs" in data:
        families = {row["fingerprint"]: row["family_id"] for row in report["secret_identities"]}
        tp = fp = fn = tn = unresolved = 0
        for pair in data["identity_pairs"]:
            a, b = pair["a"], pair["b"]
            expected = pair["same_family"]
            if not isinstance(expected, bool):
                raise ValueError("same_family must be boolean")
            if a not in families or b not in families:
                unresolved += 1
                if expected:
                    fn += 1
                continue
            predicted = families[a] == families[b]
            tp += int(expected and predicted); fp += int(not expected and predicted)
            fn += int(expected and not predicted); tn += int(not expected and not predicted)
        result["identity_correlation"] = {**classification_metrics(tp, fp, fn), "tn": tn, "unresolved_pairs": unresolved, "unit": "independently labelled fingerprint pairs; missing positive member counts as FN"}
    return result


def print_summary(report: dict[str, Any], max_findings: int) -> None:
    repo = report["repository"]
    stats = report["statistics"]
    print(f"\n{NAME} {VERSION}")
    print("=" * 84)
    print(f"Target                  : {report['target']}")
    print(f"Scope                   : {report['scope']}")
    print(f"Object format           : {repo['object_format']}")
    print(f"Objects                 : {sum(repo['object_counts'].values())}")
    print(f"  commits               : {repo['object_counts'].get('commit', 0)}")
    print(f"  trees                 : {repo['object_counts'].get('tree', 0)}")
    print(f"  blobs                 : {repo['object_counts'].get('blob', 0)}")
    print(f"  annotated tags        : {repo['object_counts'].get('tag', 0)}")
    print(f"Current objects         : {repo['state_counts']['current']}")
    print(f"Historical objects      : {repo['state_counts']['historical']}")
    print(f"Reachable objects       : {repo['state_counts']['reachable']}")
    print(f"Unreachable objects     : {repo['state_counts']['unreachable']}")
    print(f"Packed objects          : {repo['state_counts']['packed']}")
    print(f"Object graph edges      : {repo['graph_edge_count']}")
    print(f"Commits analyzed        : {repo['commits_analyzed']}")
    print(f"Path changes            : {repo['path_change_count']}")
    print(f"Lineage edges           : {stats['lineage_edges']}")
    print(f"Unique secret IDs       : {stats['unique_secrets']}")
    print(f"Secret occurrences      : {stats['occurrences']}")
    print(f"Lifecycle events        : {stats['lifecycle_events']}")
    print(f"Content-scanned objects : {stats['objects_scanned']}")
    print(f"Data scanned            : {stats['bytes_scanned_human']}")
    print(f"Duration                : {report['duration_seconds']:.3f}s")

    if report["notes"]:
        print("\nNOTES")
        for note in report["notes"]:
            print(f"  - {note}")

    print("\nRISK-PRIORITIZED FINDINGS")
    print("-" * 84)
    rows = report["prioritized_findings"]
    if not rows:
        print("No matching secret findings.")
    else:
        selected = rows if max_findings == 0 else rows[:max_findings]
        for i, x in enumerate(selected, 1):
            print(
                f"{i:03d} [{x['risk_class'].upper():8}] risk={x['final_risk']:.4f} "
                f"{x['secret_id']}  {x['path']}"
            )
            print(
                f"      blob={x['blob_oid']} commit={x['commit'] or '<unknown>'} "
                f"current={x['current']} reachable={x['reachable']} historical={x['historical']} packed={x['packed']}"
            )
            print(
                "      components: "
                f"C={x['content_confidence']:.3f} "
                f"R={x['reachability_score']:.3f} "
                f"D={x['deletion_score']:.3f} "
                f"H={x['historical_score']:.3f} "
                f"L={x['lineage_score']:.3f} "
                f"P={x['propagation_score']:.3f}"
            )
        hidden = len(rows) - len(selected)
        if hidden:
            print(f"... {hidden} more findings hidden; use --max-findings 0 to show all.")

    ev = report.get("ground_truth_evaluation")
    if ev:
        print("\nGROUND-TRUTH EVALUATION")
        print("-" * 84)
        print(
            f"TP={ev['tp']} FP={ev['fp']} TN={ev['tn']} FN={ev['fn']}  "
            f"Precision={ev['precision']} Recall={ev['recall']} F1={ev['f1']}"
        )

    print("\nEXPERIMENTAL PARAMETER NOTICE")
    print("-" * 84)
    print(report["experimental_parameters"]["warning"])


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gasld",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description=(
            "Git-Aware Secret Lifecycle Detection research prototype. "
            "Use only on authorized repositories."
        ),
    )
    p.add_argument("--repo", required=True, help="Local Git repository or authorized remote Git URL")
    p.add_argument(
        "--scope", choices=["all", "reachable", "unreachable", "current"], default="all",
        help="Content scan scope; full GASLD analysis normally uses all"
    )
    p.add_argument("--output", default="gasld-report.json", help="JSON report path")
    p.add_argument("--format", choices=["terminal", "json"], default="terminal")
    p.add_argument("--show-secrets", action="store_true", help="Show secret values (authorized lab only)")
    p.add_argument("--max-findings", type=int, default=100, help="Terminal findings; 0=all")
    p.add_argument("--max-blob-size", type=parse_size, default=MAX_BLOB_DEFAULT)
    p.add_argument(
        "--include-binary-strings", action=argparse.BooleanOptionalAction, default=True,
        help="Extract printable strings from binary blobs"
    )
    p.add_argument("--object-budget", type=int, default=0, help="Scan top N state-prioritized blobs; 0=no budget")
    p.add_argument("--max-commits", type=int, default=0, help="Analyze newest N commits in constructed order; 0=all")
    p.add_argument("--lineage-threshold", type=float, default=LINEAGE_THRESHOLD_DEFAULT)
    p.add_argument("--rotation-threshold", type=float, default=ROTATION_THRESHOLD_DEFAULT)
    p.add_argument(
        "--content-weights", default="pattern=0.50,entropy=0.20,context=0.30",
        help="Pattern/entropy/context weights"
    )
    p.add_argument(
        "--lineage-weights", default="content=0.45,path=0.25,commit=0.20,temporal=0.10",
        help="Content/path/commit/temporal lineage weights"
    )
    p.add_argument(
        "--risk-weights",
        default="content=0.30,reachability=0.15,deletion=0.15,historical=0.10,lineage=0.15,propagation=0.15",
        help="Git-aware risk weights"
    )
    p.add_argument(
        "--ground-truth",
        help='Optional manifest: {"items":[{"id":"S1","fingerprint":"sha256...","expected_secret":true}]}'
    )
    p.add_argument("--previous-report", help="Earlier v2 report from the same local repo, for ref/object retention transitions")
    p.add_argument("--risk-config", help="Calibrated JSON config from research.py calibrate; loads risk_weights")
    p.add_argument("--min-confidence", type=float, default=0.40)
    p.add_argument("--model", choices=list("ABCDE"), default="E", help="A content; B +state; C +lineage; D +propagation; E +deletion lifecycle")
    p.add_argument("--progress", action=argparse.BooleanOptionalAction, default=True)
    p.add_argument("--max-lineage-candidates", type=int, default=64)
    p.add_argument("--rules", help="Additional local JSON rules: rules=[name, regex, group, pattern_score]")
    p.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    return p


def run_engine(engine: Engine) -> None:
    own_trace = not tracemalloc.is_tracing()
    if own_trace:
        tracemalloc.start()
    phases = [("objects_and_state", engine.extract_objects_and_states),
              ("graph", engine.build_graph), ("snapshots", engine.build_snapshots),
              ("detection", engine.detect)]
    if engine.model in {"C", "D", "E"}:
        phases.append(("lineage", engine.infer_lineage))
    phases += [("correlation", engine.correlate), ("lifecycle", engine.build_lifecycle)]
    if engine.model in {"D", "E"}:
        phases.append(("propagation", engine.analyze_propagation))
    phases.append(("scoring", engine.score))
    try:
        for name, operation in phases:
            engine._progress(name, force=True)
            started = time.perf_counter()
            operation()
            engine.phase_seconds[name] = round(time.perf_counter() - started, 6)
        engine.peak_memory_bytes = tracemalloc.get_traced_memory()[1]
    finally:
        if own_trace:
            tracemalloc.stop()


def main() -> int:
    args = parser().parse_args()
    if not math.isfinite(args.min_confidence) or not 0 <= args.min_confidence <= 1 or args.max_lineage_candidates < 1:
        print("ERROR: confidence must be in [0,1]; lineage candidate limit must be positive", file=sys.stderr)
        return 2
    if args.max_findings < 0 or args.object_budget < 0 or args.max_commits < 0:
        print("ERROR: numeric limits must be >= 0", file=sys.stderr)
        return 2
    if not 0 <= args.lineage_threshold <= 1 or not 0 <= args.rotation_threshold <= 1:
        print("ERROR: thresholds must be within [0,1]", file=sys.stderr)
        return 2

    try:
        content_weights = parse_weights(args.content_weights, ("pattern", "entropy", "context"))
        lineage_weights = parse_weights(args.lineage_weights, ("content", "path", "commit", "temporal"))
        risk_weights = parse_weights(args.risk_weights, ("content", "reachability", "deletion", "historical", "lineage", "propagation"))
    except (ValueError, argparse.ArgumentTypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.risk_config:
        try:
            config = json.loads(Path(args.risk_config).read_text())
            risk_weights = parse_weights(",".join(f"{k}={v}" for k, v in config["risk_weights"].items()), tuple(RISK_WEIGHTS_DEFAULT))
        except (OSError, ValueError, KeyError, argparse.ArgumentTypeError) as exc:
            print(f"ERROR: invalid risk config: {exc}", file=sys.stderr)
            return 2

    started_at = now_iso()
    start = time.perf_counter()
    tmp: tempfile.TemporaryDirectory | None = None
    try:
        repo_path, tmp, notes = acquire(args.repo)
        repo = GitRepo(repo_path)
        repo.validate()
        engine = Engine(
            repo,
            scope=args.scope,
            max_blob_size=args.max_blob_size,
            include_binary_strings=args.include_binary_strings,
            object_budget=args.object_budget,
            max_commits=args.max_commits,
            content_weights=content_weights,
            lineage_weights=lineage_weights,
            risk_weights=risk_weights,
            lineage_threshold=args.lineage_threshold,
            rotation_threshold=args.rotation_threshold,
            min_confidence=args.min_confidence, model=args.model, progress=args.progress,
            max_lineage_candidates=args.max_lineage_candidates,
            custom_rules=Path(args.rules) if args.rules else None,
        )

        run_engine(engine)
        evaluation = engine.evaluate(Path(args.ground_truth).expanduser().resolve() if args.ground_truth else None)

        report = engine.report(
            args.repo, notes, started_at, time.perf_counter() - start,
            args.show_secrets, evaluation
        )
        if args.previous_report:
            prior = json.loads(Path(args.previous_report).read_text())
            report["repository_transitions"] = compare_snapshots(prior, report)
        out = Path(args.output).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

        if args.format == "json":
            print(json.dumps(report, indent=2, ensure_ascii=True))
        else:
            print_summary(report, args.max_findings)
            print(f"\nReport written to: {out}")
        return 0

    except (GitError, OSError, ValueError, KeyError, re.error, RecursionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nScan cancelled.", file=sys.stderr)
        return 130
    finally:
        if tmp is not None:
            tmp.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
