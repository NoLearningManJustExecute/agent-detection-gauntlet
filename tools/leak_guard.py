#!/usr/bin/env python3
"""Leak guard: keep personal data, absolute local paths and secrets out of a public repository.

Standalone and standard library only, so this file can be copied into another repository as is.

Scopes (combinable):
  --tree       tracked files plus untracked files that are not ignored
  --history    every commit reachable from any ref: author, committer, message and added lines
  --text FILE  one arbitrary file, for example a pull request body before it is posted
  --pr         the current pull request's title, body, reviews and comments (CI, GitHub REST API)
  --all        --tree and --history

Two kinds of check run on every scanned text:
  generic rules   patterns that hold nothing personal: absolute paths, non-allowlisted emails,
                  forbidden strings, secrets
  private list    salted SHA-256 hashes of private identifiers; the guard only learns that a
                  hash matched and never prints the matching text

Exit codes: 0 clean, 1 at least one hit, 2 a usage or setup problem.
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import os
import re
import string
import subprocess
import sys
import urllib.request
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ALLOW_FILE = ".leakguard-allow"
DEFAULT_DENYLIST = Path("..") / "_planning" / "private-denylist.hashes"
IMAGE_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".pdf"})
METADATA_MARKERS = (b"Exif", b"eXIf", b"EXIF", b"xmpmeta", b"XML:com.adobe.xmp")
BINARY_SNIFF_BYTES = 8192


class GuardSetupError(Exception):
    """A configuration problem that stops the scan (exit 2)."""


# ---------------------------------------------------------------- generic rules


ALLOWED_EMAIL_DOMAINS = frozenset(
    {"users.noreply.github.com", "noreply.github.com", "example.com", "example.net", "example.org"}
)
ALLOWED_GITHUB_LOCAL_PARTS = frozenset({"noreply", "support"})
ALLOWED_EMAIL_SUFFIXES = (".example", ".test", ".invalid")


def email_allowed(address: str) -> bool:
    local, _, domain = address.rpartition("@")
    domain = domain.lower()
    if domain in ALLOWED_EMAIL_DOMAINS:
        return True
    if domain == "github.com":
        return local.lower() in ALLOWED_GITHUB_LOCAL_PARTS
    return domain.endswith(ALLOWED_EMAIL_SUFFIXES)


def runner_home_allowed(match: str, origin: str | None) -> bool:
    """The CI runner's home directory may appear in workflow files only."""
    return (
        origin is not None
        and origin.startswith(".github/")
        and re.fullmatch(r"/home/runner(/.*)?", match) is not None
    )


@dataclass(frozen=True)
class GenericRule:
    name: str
    pattern: re.Pattern[str]
    allowed: Callable[[str, str | None], bool] | None = None


# Several patterns are assembled from pieces so that this file never matches its own rules.
GENERIC_RULES: tuple[GenericRule, ...] = (
    GenericRule("windows-path", re.compile(r"(?<![A-Za-z])[A-Za-z]:[\\/][^\s\"'`<>|*?]*")),
    GenericRule("unc-path", re.compile(r"(?<![\\\w])\\\\[A-Za-z0-9][\w.$-]*\\[\w.$-]+")),
    GenericRule("macos-home-path", re.compile(r"/Users/[A-Za-z0-9._-]+")),
    GenericRule(
        "linux-home-path",
        re.compile(r"/home/[A-Za-z0-9._-]+[^\s\"'`<>|]*"),
        lambda match, origin: runner_home_allowed(match, origin),
    ),
    GenericRule("userprofile-variable", re.compile("%" + "USERPROFILE" + "%", re.IGNORECASE)),
    GenericRule("home-tilde-path", re.compile(r"~[\\/][A-Za-z0-9._-]+")),
    GenericRule(
        "email-address",
        re.compile(r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}"),
        lambda match, origin: email_allowed(match),
    ),
    GenericRule("forbidden-domain", re.compile(re.escape("anthropic" + ".com"), re.IGNORECASE)),
    GenericRule("forbidden-domain", re.compile(re.escape("claude" + ".ai"), re.IGNORECASE)),
    GenericRule("generated-footer", re.compile("Generated" + r"\s+with", re.IGNORECASE)),
    GenericRule("session-id", re.compile("session" + r"_\w{20,}")),
    GenericRule("dash-character", re.compile("[" + chr(0x2013) + chr(0x2014) + "]")),
    GenericRule("private-key", re.compile("-{5}BEGIN " + r"(?:[A-Z0-9]+ )*PRIVATE KEY-{5}")),
    GenericRule("github-token", re.compile(r"(?<![A-Za-z0-9])gh[oprsu]_[A-Za-z0-9]{20,}")),
    GenericRule("github-token", re.compile("github" + r"_pat_[A-Za-z0-9_]{20,}")),
    GenericRule("api-key", re.compile(r"(?<![A-Za-z0-9-])sk-[A-Za-z0-9_-]{20,}")),
    GenericRule("slack-token", re.compile(r"(?<![A-Za-z0-9])xox[bp]-[A-Za-z0-9-]{10,}")),
    GenericRule("aws-access-key", re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![0-9A-Z])")),
)


def mask(text: str) -> str:
    """Show only the two characters at each end of a match."""
    if len(text) <= 6:
        return "*" * len(text)
    return f"{text[:2]}****{text[-2:]}"


# ---------------------------------------------------------------- private denylist


_EDGE_PUNCTUATION = string.punctuation + "".join(map(chr, (0x201C, 0x201D, 0x2018, 0x2019)))


@dataclass(frozen=True)
class Token:
    word: str
    line: int


@dataclass(frozen=True)
class Denylist:
    salt: str
    max_words: int
    entries: Mapping[str, int]

    @classmethod
    def parse(cls, text: str) -> Denylist:
        """Parse ``salt``, ``maxwords`` and ``hash`` lines. Errors never echo line content."""
        salt: str | None = None
        max_words: int | None = None
        entries: dict[str, int] = {}
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition(" ")
            value = value.strip()
            if key == "salt" and re.fullmatch(r"[0-9a-fA-F]+", value) and salt is None:
                salt = value
            elif key == "maxwords" and value.isdigit() and int(value) >= 1 and max_words is None:
                max_words = int(value)
            elif key == "hash" and re.fullmatch(r"[0-9a-f]{64}", value):
                entries.setdefault(value, len(entries) + 1)
            else:
                raise GuardSetupError(f"denylist line {number} is not a valid entry")
        if salt is None or max_words is None:
            raise GuardSetupError("denylist needs exactly one salt line and one maxwords line")
        if not entries:
            raise GuardSetupError("denylist holds no hash lines")
        return cls(salt=salt, max_words=max_words, entries=entries)

    def digest(self, identifier: str) -> str:
        data = f"{self.salt}\n{identifier.strip().lower()}"
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def matches(self, text: str) -> Iterator[tuple[int, int]]:
        """Yield (line, entry number) for each whole-word window whose hash is listed."""
        base = hashlib.sha256(f"{self.salt}\n".encode())
        seen: set[tuple[int, int]] = set()
        for tokens in token_streams(text):
            for start in range(len(tokens)):
                window: list[str] = []
                for token in tokens[start : start + self.max_words]:
                    window.append(token.word)
                    hasher = base.copy()
                    hasher.update(" ".join(window).encode("utf-8"))
                    entry = self.entries.get(hasher.hexdigest())
                    hit = (tokens[start].line, entry or 0)
                    if entry is not None and hit not in seen:
                        seen.add(hit)
                        yield hit


def token_streams(text: str) -> list[list[Token]]:
    """Three word streams over the lowercased text, each word tagged with its line.

    Whitespace words as written, the same words without edge punctuation, and runs of letters and
    digits. A window is always made of whole words, so a listed word inside a longer word does
    not match, while a listed word inside a path or an address still does.
    """
    lowered = text.lower()
    starts = [0] + [index + 1 for index, char in enumerate(lowered) if char == "\n"]

    def line_of(offset: int) -> int:
        return bisect.bisect_right(starts, offset)

    raw = [Token(m.group(), line_of(m.start())) for m in re.finditer(r"\S+", lowered)]
    stripped = [
        Token(word, token.line) for token in raw if (word := token.word.strip(_EDGE_PUNCTUATION))
    ]
    alnum = [Token(m.group(), line_of(m.start())) for m in re.finditer(r"[^\W_]+", lowered)]
    return [raw, stripped, alnum] if stripped != raw else [raw, alnum]


# ---------------------------------------------------------------- allowlist


@dataclass(frozen=True)
class Allowlist:
    values: frozenset[str] = frozenset()

    @classmethod
    def parse(cls, text: str, denylist: Denylist | None) -> Allowlist:
        values: set[str] = set()
        for number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            value, sep, reason = line.rpartition(" # ")
            value = value.rstrip()
            if not sep or not value or not reason.strip():
                raise GuardSetupError(
                    f"{ALLOW_FILE} line {number}: use '<exact string> # <reason>'"
                )
            if denylist is not None:
                for _, entry in denylist.matches(line):
                    raise GuardSetupError(
                        f"{ALLOW_FILE} line {number} contains a private identifier "
                        f"(hash #{entry}); the allowlist can never hold one"
                    )
            values.add(value)
        return cls(frozenset(values))

    def permits(self, found: str, whole_line: str, origin: str | None) -> bool:
        """A generic match passes when an entry equals the match or the whole trimmed line.

        Inside the allowlist file itself, a match that sits within an entry passes too. Denylist
        hits never consult this method.
        """
        if found in self.values or whole_line in self.values:
            return True
        return origin == ALLOW_FILE and any(found in value for value in self.values)


# ---------------------------------------------------------------- scanning


@dataclass(frozen=True)
class Hit:
    location: str
    rule: str
    shown: str

    def render(self) -> str:
        return f"{self.location}: {self.rule}: {self.shown}"


@dataclass
class Scanner:
    denylist: Denylist | None
    allowlist: Allowlist = field(default_factory=Allowlist)
    hits: list[Hit] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)

    def scan_text(
        self,
        text: str,
        label: str,
        *,
        origin: str | None = None,
        line_map: Sequence[int] | None = None,
    ) -> None:
        """Scan ``text`` and record hits as ``label:line``.

        ``origin`` is the repository path the text belongs to, for path-scoped exceptions.
        ``line_map`` maps the 1-based line of ``text`` to the line number to report.
        """

        def where(line: int) -> str:
            shown = line_map[line - 1] if line_map is not None else line
            return f"{label}:{shown}"

        starts = [0] + [index + 1 for index, char in enumerate(text) if char == "\n"]
        for rule in GENERIC_RULES:
            for match in rule.pattern.finditer(text):
                found = match.group()
                line = bisect.bisect_right(starts, match.start())
                end = text.find("\n", match.start())
                whole_line = text[starts[line - 1] : len(text) if end < 0 else end].strip()
                if self.allowlist.permits(found, whole_line, origin):
                    continue
                if rule.allowed is not None and rule.allowed(found, origin):
                    continue
                private = self.denylist is not None and any(self.denylist.matches(found))
                self.hits.append(Hit(where(line), rule.name, "****" if private else mask(found)))
        if self.denylist is not None:
            for line, entry in self.denylist.matches(text):
                self.hits.append(
                    Hit(where(line), "denylist", f"private identifier (hash #{entry})")
                )

    def scan_image(self, data: bytes, label: str) -> None:
        self.notices.append(f"{label}: image, needs manual review")
        if any(marker in data for marker in METADATA_MARKERS):
            self.hits.append(Hit(label, "image-metadata", "EXIF or XMP metadata present"))

    def scan_file_bytes(self, data: bytes, label: str) -> None:
        suffix = Path(label).suffix.lower()
        if suffix in IMAGE_SUFFIXES:
            self.scan_image(data, label)
        if b"\0" in data[:BINARY_SNIFF_BYTES]:
            return
        self.scan_text(data.decode("utf-8", errors="replace"), label, origin=label)


def run_git(root: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-c", "core.quotepath=off", *args], cwd=root, capture_output=True, check=False
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise GuardSetupError(f"git {args[0]} failed: {message}")
    return result.stdout


def tree_files(root: Path) -> list[str]:
    output = run_git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard")
    return sorted({name for name in output.decode("utf-8").split("\0") if name})


def scan_tree(scanner: Scanner, root: Path) -> None:
    for name in tree_files(root):
        path = root / name
        if not path.is_file():
            continue
        scanner.scan_text(name, f"{name} (file name)", origin=name)
        scanner.scan_file_bytes(path.read_bytes(), name)


@dataclass
class FilePatch:
    path: str
    lines: list[str] = field(default_factory=list)
    numbers: list[int] = field(default_factory=list)


def _patch_path(header: str) -> str:
    name = header[4:].strip()
    if name.startswith('"') and name.endswith('"'):
        name = name[1:-1]
    return name[2:] if name.startswith("b/") else name


def parse_patch(patch: str) -> list[FilePatch]:
    """Added lines of a unified diff, grouped by file, with their new-file line numbers."""
    files: list[FilePatch] = []
    current: FilePatch | None = None
    number = 0
    for line in patch.splitlines():
        if line.startswith("diff --git "):
            current = None
        elif line.startswith("+++ "):
            current = None if line[4:].strip() == "/dev/null" else FilePatch(_patch_path(line))
            if current is not None:
                files.append(current)
        elif line.startswith("@@"):
            found = re.search(r"\+(\d+)", line)
            number = int(found.group(1)) if found else 0
        elif current is not None and line.startswith("+"):
            current.lines.append(line[1:])
            current.numbers.append(number)
            number += 1
        elif line.startswith(" "):
            number += 1
    return files


HISTORY_FORMAT = "%x00%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B%x00"
HISTORY_FIELDS = ("author name", "author email", "committer name", "committer email")


def scan_history(scanner: Scanner, root: Path) -> None:
    output = run_git(
        root,
        "log",
        "--all",
        "-p",
        "--unified=0",
        "--no-color",
        "--no-ext-diff",
        "--no-renames",
        "--diff-merges=first-parent",
        f"--format={HISTORY_FORMAT}",
    ).decode("utf-8", errors="replace")
    parts = output.split("\0")[1:]
    for index in range(0, len(parts) - 6, 7):
        sha, *people, message, patch = parts[index : index + 7]
        commit = f"commit {sha[:12]}"
        for name, value in zip(HISTORY_FIELDS, people, strict=True):
            scanner.scan_text(value, f"{commit} {name}")
        scanner.scan_text(message, f"{commit} message")
        for file_patch in parse_patch(patch):
            scanner.scan_text(file_patch.path, f"{commit} {file_patch.path} (file name)")
            if file_patch.lines:
                scanner.scan_text(
                    "\n".join(file_patch.lines),
                    f"{commit} {file_patch.path}",
                    origin=file_patch.path,
                    line_map=file_patch.numbers,
                )
    scan_history_images(scanner, root)


def scan_history_images(scanner: Scanner, root: Path) -> None:
    """Check every image blob reachable from any ref for EXIF or XMP metadata."""
    listing = run_git(root, "rev-list", "--objects", "--all").decode("utf-8", errors="replace")
    seen: set[str] = set()
    for line in listing.splitlines():
        sha, _, name = line.partition(" ")
        if not name or Path(name).suffix.lower() not in IMAGE_SUFFIXES or sha in seen:
            continue
        seen.add(sha)
        scanner.scan_image(run_git(root, "cat-file", "blob", sha), f"history blob {name}")


# ---------------------------------------------------------------- pull request text


def http_get_json(url: str, token: str) -> Any:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def _all_pages(url: str, token: str) -> Iterator[dict[str, Any]]:
    page = 1
    while True:
        batch = http_get_json(f"{url}?per_page=100&page={page}", token)
        if not isinstance(batch, list):
            raise GuardSetupError("unexpected response from the GitHub API")
        yield from batch
        if len(batch) < 100:
            return
        page += 1


def pull_request_texts(env: Mapping[str, str]) -> list[tuple[str, str]]:
    """Title, body, reviews, review comments and comments of the pull request under test."""
    token = env.get("GITHUB_TOKEN", "")
    repository = env.get("GITHUB_REPOSITORY", "")
    event_path = env.get("GITHUB_EVENT_PATH", "")
    if not token or not repository or not event_path:
        raise GuardSetupError("--pr needs GITHUB_TOKEN, GITHUB_REPOSITORY and GITHUB_EVENT_PATH")
    event = json.loads(Path(event_path).read_text(encoding="utf-8"))
    number = event.get("pull_request", {}).get("number")
    if not isinstance(number, int):
        raise GuardSetupError("--pr runs only on pull_request events")
    base = f"{env.get('GITHUB_API_URL', 'https://api.github.com')}/repos/{repository}"
    pr = http_get_json(f"{base}/pulls/{number}", token)
    texts = [("pr title", str(pr.get("title") or "")), ("pr body", str(pr.get("body") or ""))]
    sources = (
        ("pr review", f"{base}/pulls/{number}/reviews"),
        ("pr review comment", f"{base}/pulls/{number}/comments"),
        ("pr comment", f"{base}/issues/{number}/comments"),
    )
    for kind, url in sources:
        for item in _all_pages(url, token):
            texts.append((f"{kind} {item.get('id')}", str(item.get("body") or "")))
    return texts


# ---------------------------------------------------------------- setup


def find_root(start: Path) -> Path:
    try:
        output = run_git(start, "rev-parse", "--show-toplevel")
    except (GuardSetupError, OSError):
        return Path(__file__).resolve().parents[1]
    return Path(output.decode("utf-8").strip())


def load_denylist(env: Mapping[str, str], root: Path) -> tuple[Denylist | None, str]:
    """Denylist and a description of its source, or (None, reason) when there is none."""
    named = env.get("LEAK_DENYLIST_FILE", "")
    if named:
        path = Path(named)
        if not path.is_file():
            raise GuardSetupError("LEAK_DENYLIST_FILE does not name a readable file")
        return Denylist.parse(path.read_text(encoding="utf-8")), "LEAK_DENYLIST_FILE"
    inline = env.get("LEAK_DENYLIST", "")
    if inline.strip():
        return Denylist.parse(inline), "LEAK_DENYLIST"
    default = root / DEFAULT_DENYLIST
    if default.is_file():
        return Denylist.parse(default.read_text(encoding="utf-8")), "private planning file"
    return None, "no source"


def display_name(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leak_guard",
        description="Block personal data, absolute paths and secrets from reaching a remote.",
    )
    parser.add_argument("--tree", action="store_true", help="scan the working tree")
    parser.add_argument("--history", action="store_true", help="scan every reachable commit")
    parser.add_argument("--text", action="append", type=Path, default=[], metavar="FILE")
    parser.add_argument("--pr", action="store_true", help="scan the current pull request text")
    parser.add_argument("--all", action="store_true", help="same as --tree --history")
    parser.add_argument("--root", type=Path, help="repository root (default: from git)")
    return parser


def run(args: argparse.Namespace, env: Mapping[str, str]) -> int:
    root = (args.root or find_root(Path.cwd())).resolve()
    tree = args.tree or args.all
    history = args.history or args.all
    if not (tree or history or args.text or args.pr):
        raise GuardSetupError("choose at least one scope: --tree, --history, --text, --pr, --all")

    denylist, source = load_denylist(env, root)
    if denylist is None:
        print(
            "WARNING: no private denylist found (LEAK_DENYLIST_FILE, LEAK_DENYLIST or the "
            "private planning file). Private identifiers are NOT being checked.",
            file=sys.stderr,
        )
        if env.get("CI", "").lower() == "true":
            print("error: a denylist is required in CI", file=sys.stderr)
            return 2
    allow_path = root / ALLOW_FILE
    allowlist = (
        Allowlist.parse(allow_path.read_text(encoding="utf-8"), denylist)
        if allow_path.is_file()
        else Allowlist()
    )
    scanner = Scanner(denylist=denylist, allowlist=allowlist)

    scopes: list[str] = []
    if tree:
        scopes.append("tree")
        scan_tree(scanner, root)
    if history:
        scopes.append("history")
        scan_history(scanner, root)
    for path in args.text:
        scopes.append("text")
        if not path.is_file():
            raise GuardSetupError(f"--text file not found: {display_name(path, root)}")
        scanner.scan_file_bytes(path.read_bytes(), display_name(path, root))
    if args.pr:
        scopes.append("pr")
        for label, text in pull_request_texts(env):
            scanner.scan_text(text, label)

    for notice in scanner.notices:
        print(f"notice: {notice}")
    for hit in scanner.hits:
        print(hit.render())
    entries = "no denylist" if denylist is None else f"denylist {len(denylist.entries)} entries"
    summary = f"({', '.join(dict.fromkeys(scopes))}; {entries} from {source})"
    if scanner.hits:
        print(f"leak guard: {len(scanner.hits)} hit(s) {summary}", file=sys.stderr)
        return 1
    print(f"leak guard: clean {summary}")
    return 0


def main(argv: Sequence[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return run(args, os.environ if env is None else env)
    except GuardSetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: {exc.strerror or exc.__class__.__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
