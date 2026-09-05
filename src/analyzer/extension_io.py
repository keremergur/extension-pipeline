"""Reading extension source and building beautified code context.

Shared by every tool adapter: given a set of {filename: [(start, end), ...]}
line references, produce a readable, beautified code excerpt for the prompt.

The amount of surrounding source shown is controlled by `mode` (feature 3):

    "lines"     -- N lines before/after each referenced range (ORIGINAL behaviour)
    "block"     -- the enclosing brace block around each referenced range
    "callsites" -- "block" PLUS the enclosing block of every textual call site of
                   those blocks' declared names (1 hop, capped)
    "symbols"   -- "block" PLUS the definitions and uses of the identifiers the
                   model itself asked for on the previous attempt
    "module"    -- the enclosing bundler module (webpack/browserify) around each
                   referenced range, instead of the whole bundle
    "toplevel"  -- HIGH_TIER_CONTEXT_BASE PLUS every depth-0 statement in the file
                   (where the extension's listener/storage wiring lives)
    "skeleton"  -- "toplevel" PLUS every function-opening line, so the file's
                   structure is visible without its bodies
    "packed"    -- "block" PLUS as many other chunks of the file as fit a token
                   budget, best-matching first (rank-and-fill)
    "file"      -- the entire file(s) that contain a referenced range
    "used"      -- every file referenced anywhere in the report, in full
                   (uses `all_line_refs`; drops files the report never references)

The middle scopes exist because the jump from "block" to "file" was the pipeline's
largest data-loss source: on bundled JS a file is a median 2.9x and a p90 56x
larger render than its enclosing block, so a third of all escalations built a
prompt that could not be sent (see EXPERIMENTS.md 25-26).

NAMING (renamed after run results_vllm_2026-08-26_23-58-37; old names still accepted
via MODE_ALIASES):

    "function" -> "block"      The scope is not the enclosing *function*. It is the
                               enclosing brace block: `_enclosing_block` walks up
                               until a block's opening line passes a heuristic
                               function test, and falls back to the nearest brace
                               block when nothing does. On minified-then-beautified
                               code that fallback is common, so "block" is what the
                               model actually receives.
    "callers"  -> "callsites"  These are textual `name(` matches, not a resolved
                               call graph. Compressed extensions name functions in
                               1-2 characters, so name matching cannot be trusted
                               to mean "caller"; short and over-frequent names are
                               skipped outright rather than guessed at.

Every scope except "packed" is deterministic given the file and the refs. "lines"
through "module" and "file"/"used" are byte-identical to their pre-existing output;
the discontiguous scopes mark their gaps with elision markers.

HIGH-TIER BASE (added 09-03, EXPERIMENTS.md 33.2-33.3 / D124 / E38):

    "toplevel" and "skeleton" used to keep the narrow enclosing BLOCK whole and then
    jump straight to depth 0. That left a gap at exactly the nesting levels in
    between -- in a bundle, where the onConnectExternal/onMessageExternal
    registration and its gate checks sit -- so escalating from "module" to
    "toplevel" could elide evidence the model had already been shown one attempt
    earlier, turning a correct confident TP into a confident FP. The tiers were not
    nested: "toplevel" was wider than "module" in cost and rank, but not in content.

    `HIGH_TIER_CONTEXT_BASE` (default "module") is the scope those two keep whole
    underneath what they add, which restores containment:

        block subset module subset toplevel subset skeleton

    Set it to "block" to reproduce any run before 09-03 byte-identically.
"""

import hashlib
import re
from pathlib import Path
from typing import List, Optional, Tuple

import jsbeautifier

import config

# Every valid scope, ordered by measured median prompt cost (EXPERIMENTS.md 26.2).
# This is the RANK order: it validates a configured mode and decides what counts as
# "wider" than what. The ladder actually walked during escalation is
# config.CONTEXT_ESCALATION_ORDER, which may list a subset in a different order.
CONTEXT_MODES = ["lines", "block", "callsites", "symbols", "module", "toplevel",
                 "skeleton", "packed", "file", "used"]

# Pre-26.8 scope names, still accepted wherever a mode is configured so existing
# env files, dataset overrides and `requested_context_scope` answers keep working.
MODE_ALIASES = {"function": "block", "callers": "callsites"}

# Scopes that render a discontiguous subset of a file and therefore mark the gaps.
SPARSE_MODES = {"callsites", "symbols", "toplevel", "skeleton", "packed"}

# Scopes that need something beyond the file and the refs to render, and therefore
# degrade to "block" when it is absent (with the reason stated in the header).
CONTEXTUAL_MODES = {"symbols", "packed"}

# Scopes built as "keep a narrower scope whole, then add lines from across the file".
# What they keep whole is config.HIGH_TIER_CONTEXT_BASE rather than a fixed "block";
# see the module docstring for why (D124: a fixed "block" base elided the very lines
# that establish external reachability).
HIGH_TIER_MODES = ("toplevel", "skeleton")
HIGH_TIER_BASES = ("lines", "block", "module")
_HIGH_TIER_BASE_DEFAULT = "module"

# What the prompt header calls each base, so an archived prompt records which base
# built it -- the A/B in E39 is unreadable otherwise.
_HIGH_TIER_BASE_LABEL = {"lines": "referenced lines",
                         "block": "enclosing blocks",
                         "module": "enclosing bundler modules"}

# `callsites`: per declared name, at most this many call sites are pulled in. A name
# occurring more often than `_CALLSITES_MAX_HITS` is a minified alias (a one-letter
# helper used 400 times) and is skipped entirely, as is any name shorter than
# `_MIN_IDENT_LEN` -- compressed extensions rename everything to 1-2 characters, and
# a match on those means nothing.
_CALLSITES_MAX_SITES = 8
_CALLSITES_MAX_HITS = 40
_MIN_IDENT_LEN = 3

# `symbols`: caps on resolving the identifiers the model asked for. Same minification
# reasoning: a requested name that is 1-2 characters, or that occurs on more lines
# than _SYMBOL_MAX_HITS, is refused rather than resolved to noise.
_SYMBOL_MAX_NAMES = 8
_SYMBOL_MAX_SITES = 6
_SYMBOL_MAX_HITS = 40

# A single resolved site must not drag in an arbitrarily large block: in a bundle the
# enclosing block of a hit can be the whole module map. Past this many lines the span
# degrades to a window centred on the hit -- measured, one `symbols` render reached
# 1_012_622 tokens without it.
_MAX_SITE_SPAN_LINES = 200

# `packed`: a chunk larger than budget/_PACK_CHUNK_DIVISOR is split into its child
# blocks, so a bundle's single top-level module map becomes one chunk per module
# rather than one chunk for the file.
_PACK_CHUNK_DIVISOR = 8
_PACK_MAX_SPLIT_DEPTH = 6
# Tokens are estimated exactly as llm_client.estimate_token_count does (~3 chars
# per token on code); duplicated rather than imported to keep this module free of
# the LLM layer.
_CHARS_PER_TOKEN = 3

# `module`: a candidate wrapper covering more than this share of the file is the
# bundle's own outer IIFE, not a module -- stop before swallowing the whole file.
# Measured at 0.9 this still let a 289k-line bundle return 4.1M tokens (vs 4.35M for
# the whole file), i.e. the rung bought nothing; half a bundle is not a module.
_MODULE_MAX_SHARE = 0.5


def read_file_safe(file_path: Path) -> Optional[str]:
    """Safely read a text file, returning None on any failure."""
    try:
        if file_path.exists():
            return file_path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        pass
    return None


def beautify_js(content: str) -> str:
    """Beautify minified JavaScript with a content-hash disk cache."""
    cache_dir = config.BEAUTIFY_CACHE_DIR
    cache_dir.mkdir(parents=True, exist_ok=True)

    content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
    cache_file = cache_dir / f"{content_hash}.js"

    if cache_file.exists():
        try:
            return cache_file.read_text(encoding='utf-8')
        except Exception:
            pass  # fall through and re-beautify

    try:
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        beautified = jsbeautifier.beautify(content, opts)
        try:
            cache_file.write_text(beautified, encoding='utf-8')
        except Exception:
            pass  # cache write failure is non-fatal
        return beautified
    except Exception:
        return content


def _load_file_lines(ext_dir: Path, filename: str) -> Optional[Tuple[List[str], bool]]:
    """Locate and read an extension file, beautifying JS.

    Returns (lines, beautified) or None if the file can't be found/read.
    """
    file_path = ext_dir / "opgen_generated_files" / filename
    if not file_path.exists():
        file_path = ext_dir / filename
    if not file_path.exists():
        # Last resort: some reports give only a bare filename for a nested file.
        # Match by basename anywhere under the extension directory.
        try:
            matches = list(ext_dir.rglob(Path(filename).name))
        except Exception:
            matches = []
        if len(matches) == 1:
            file_path = matches[0]
        else:
            return None
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            file_lines = f.readlines()
    except Exception:
        return None

    if filename.endswith('.js'):
        beautified = beautify_js(''.join(file_lines))
        return beautified.splitlines(keepends=True), True
    return file_lines, False


def _merge_ranges(ranges: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Merge overlapping/adjacent (start, end) ranges (1-indexed, inclusive)."""
    merged: List[Tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _emit(output: List[str], file_lines: List[str], merged: List[Tuple[int, int]]) -> None:
    """Append numbered source lines for each merged range, blank line between."""
    for idx, (start, end) in enumerate(merged):
        for i in range(start - 1, end):
            if 0 <= i < len(file_lines):
                output.append(f"{i+1:4d} | {file_lines[i].rstrip()}\n")
        if idx < len(merged) - 1:
            output.append("\n")


def _emit_sparse(output: List[str], file_lines: List[str], keep) -> None:
    """Append the kept lines only, marking each gap with how much was dropped.

    Used by the discontiguous scopes ("callsites"/"symbols"/"toplevel"/"skeleton"/
    "packed"), where the
    model must be able to tell "nothing here" from "something here I was not shown".
    """
    prev = None
    for i in sorted(keep):
        if not 1 <= i <= len(file_lines):
            continue
        if prev is not None and i > prev + 1:
            output.append(f"     | ... {i - prev - 1} line(s) elided ...\n")
        output.append(f"{i:4d} | {file_lines[i-1].rstrip()}\n")
        prev = i


# --- enclosing-block detection (mode="block") -------------------------------
# Heuristic, operating on beautified source: JS has no cheap exact parser here, so
# we match braces on a comment/string-stripped view of each line. Good enough on
# beautified code; may over/under-shoot on pathological minification (documented).

# A brace-opening line that begins a control-flow block, NOT a function. Excluded
# so `if (x) {` / `for (...) {` are not mistaken for a `name(args) {` method.
_CONTROL_KW = {"if", "for", "while", "switch", "catch", "with", "do", "else",
               "return", "typeof", "in", "of", "await", "yield"}
# method / function-expression shorthand:  [async] [static] [get|set] name(args) {
_METHOD_RE = re.compile(
    r'^\s*(?:async\s+)?(?:static\s+)?(?:get\s+|set\s+)?'
    r'(?P<name>[\w$]+)\s*\([^;{}]*\)\s*\{?\s*$'
)


def _looks_like_function(line: str) -> bool:
    """True if `line` opens a function/method/class (heuristic, beautified code)."""
    code = _code_only(line)
    if re.search(r'\bfunction\b', code) or '=>' in code or re.search(r'\bclass\b', code):
        return True
    m = _METHOD_RE.match(code)
    return bool(m and m.group("name") not in _CONTROL_KW)


def _code_only(line: str) -> str:
    """Blank out line comments and string/template contents to de-noise braces."""
    line = re.sub(r'//.*$', '', line)
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])*'", "''", line)
    line = re.sub(r'`(?:\\.|[^`\\])*`', '``', line)
    return line


def _enclosing_braces(lines: List[str], s: int, e: int) -> Optional[Tuple[int, int]]:
    """Smallest `{...}` block (1-indexed, inclusive) strictly containing [s, e]."""
    n = len(lines)
    depth, open_line = 0, None
    for i in range(min(s, n), 0, -1):
        for ch in reversed(_code_only(lines[i - 1])):
            if ch == '}':
                depth += 1
            elif ch == '{':
                if depth == 0:
                    open_line = i
                    break
                depth -= 1
        if open_line is not None:
            break
    if open_line is None:
        return None

    depth, close_line = 0, None
    for i in range(max(e, 1), n + 1):
        for ch in _code_only(lines[i - 1]):
            if ch == '{':
                depth += 1
            elif ch == '}':
                if depth == 0:
                    close_line = i
                    break
                depth -= 1
        if close_line is not None:
            break
    if close_line is None:
        return None
    return (open_line, close_line)


def _enclosing_block(lines: List[str], start: int, end: int) -> Tuple[int, int]:
    """Expand [start, end] outward to the enclosing block.

    Walks up enclosing brace blocks until the block's opening line looks like a
    function/method/class (or top-level is reached). Falls back to the nearest
    brace block, or the original range if none is found.
    """
    lo, hi = start, end
    for _ in range(25):  # cap: avoid pathological expansion loops
        block = _enclosing_braces(lines, lo, hi)
        if block is None:
            break
        blo, bhi = block
        if blo == 1 or _looks_like_function(lines[blo - 1]):
            return blo, bhi
        new_lo = blo - 1 if blo > 1 else blo
        new_hi = bhi + 1 if bhi < len(lines) else bhi
        if (new_lo, new_hi) == (lo, hi):
            break
        lo, hi = new_lo, new_hi
    fallback = _enclosing_braces(lines, start, end)
    return fallback if fallback else (start, end)


# --- depth-0 statements (modes "toplevel" / "skeleton") ---------------------

def _toplevel_lines(file_lines: List[str]) -> set:
    """1-indexed line numbers that sit at brace depth 0.

    A line counts when it is at depth 0 *before* it (so `function f() {` is kept,
    which is what makes the skeleton readable) or back at depth 0 *after* it (so the
    matching `}` is kept too). In extension code this is where the load-bearing
    wiring lives: `chrome.runtime.onMessage.addListener(...)`, `chrome.storage`
    setup, permission-adjacent globals and module registration.
    """
    keep = set()
    depth = 0
    for i, text in enumerate(file_lines, 1):
        before = depth
        code = _code_only(text)
        depth += code.count('{') - code.count('}')
        if before <= 0 or depth <= 0:
            keep.add(i)
    return keep


# --- enclosing bundler module (mode="module") -------------------------------
# A webpack/browserify bundle is one enormous file made of small modules, so the
# useful unit above "block" is the module, not the file. Two signals mark one:
# the wrapper's argument list, and the `"id": function(...) {` / `42: (a,b)=>{`
# shape of an entry in the module map.

_MODULE_HINT_RE = re.compile(
    r'\b(?:__webpack_require__|__unused_webpack_\w+|webpackJsonp|webpackChunk)\b'
    r'|\bmodule\s*,\s*exports\b'
    r'|\bexports\s*,\s*require\b'
)
_MODULE_KEY_RE = re.compile(
    r'^\s*(?:/\*+[^*]*\*+/\s*)*'                    # optional /* 42 */ marker
    r'(?:"[^"]+"|\'[^\']+\'|\d+)\s*:\s*'            # "id": / 'id': / 42:
    r'(?:function\s*[\w$]*\s*)?\([^)]*\)\s*(?:=>\s*)?\{\s*$'
)


def _looks_like_module(line: str) -> bool:
    """True if `line` opens a bundler module wrapper (heuristic)."""
    code = _code_only(line)
    return bool(_MODULE_HINT_RE.search(code) or _MODULE_KEY_RE.match(code))


def _depth_profile(file_lines: List[str]) -> Tuple[List[int], List[int]]:
    """Brace depth before and after each line, computed in one pass.

    Hoisted out of `_enclosing_module` because a CodeQL finding carries one line
    range per data-flow node, and recomputing this per range made `module` cost
    seconds on a 289k-line bundle.
    """
    before, depth = [], 0
    for text in file_lines:
        before.append(depth)
        code = _code_only(text)
        depth += code.count('{') - code.count('}')
    return before, before[1:] + [depth]


def _enclosing_module(file_lines: List[str], start: int, end: int,
                      profile: Optional[Tuple[List[int], List[int]]] = None) -> Tuple[int, int]:
    """Widen [start, end] to the enclosing bundler module.

    Walks up brace blocks from the enclosing function and stops at the first one
    that looks like a module wrapper. With no wrapper in sight (hand-written code,
    or a bundler shape the heuristic does not know) it returns the widest enclosing
    block that still covers at most `_MODULE_MAX_SHARE` of the file, so the bundle's
    own outer IIFE never counts as "the module".
    """
    n = len(file_lines)
    lo, hi = _enclosing_block(file_lines, start, end)
    if _looks_like_module(file_lines[lo - 1]):
        return lo, hi

    # Walk up on the depth profile rather than by re-running _enclosing_braces,
    # which rescans the file character by character on every level.
    before, after = profile if profile is not None else _depth_profile(file_lines)

    # One backward and one forward sweep collect the block boundary for EVERY level
    # at once. Rescanning per level instead is O(n x depth) and cost seconds on the
    # deepest bundles.
    start_level = before[lo - 1]
    opens, closes = {}, {}
    for i in range(lo - 1, 0, -1):
        b = before[i - 1]
        if b < start_level and b not in opens:
            opens[b] = i
            if b == 0:
                break
    for j in range(hi + 1, n + 1):
        a = after[j - 1]
        if a < start_level and a not in closes:
            closes[a] = j
            if a == 0:
                break

    best = (lo, hi)
    for level in range(start_level - 1, -1, -1):
        open_line, close_line = opens.get(level), closes.get(level)
        if open_line is None or close_line is None:
            break
        if (close_line - open_line + 1) > _MODULE_MAX_SHARE * n:
            break
        if _looks_like_module(file_lines[open_line - 1]):
            return open_line, close_line
        best = (open_line, close_line)
    return best


# --- 1-hop call neighbourhood (mode="callsites") ----------------------------

_NAME_RES = [
    re.compile(r'\bfunction\s+([\w$]+)\s*\('),                        # function f(
    re.compile(r'\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s*)?(?:function\b|\()'),
    re.compile(r'^\s*["\']?([\w$]+)["\']?\s*:\s*(?:async\s*)?(?:function\b|\()'),
    re.compile(r'^\s*(?:async\s+)?(?:static\s+)?(?:get\s+|set\s+)?([\w$]+)\s*\('),
]


def _declared_name(line: str) -> Optional[str]:
    """Best-effort name declared by a block-opening line."""
    code = _code_only(line)
    for rx in _NAME_RES:
        m = rx.search(code)
        if m:
            name = m.group(1)
            if name not in _CONTROL_KW and len(name) >= _MIN_IDENT_LEN:
                return name
    return None


def _callsite_spans(file_lines: List[str],
                    fn_spans: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Enclosing blocks of the textual call sites of `fn_spans`' declared names.

    One hop only, and deliberately conservative: a name that occurs more than
    `_CALLSITES_MAX_HITS` times is a minified alias whose call sites carry no
    information, and at most `_CALLSITES_MAX_SITES` sites are taken per name, so the
    scope cannot quietly expand to the whole file.
    """
    names = {n for n in (_declared_name(file_lines[s - 1]) for s, _ in fn_spans) if n}
    spans: List[Tuple[int, int]] = []
    for name in sorted(names):
        call_re = re.compile(r'\b' + re.escape(name) + r'\s*\(')
        hits = [i for i, t in enumerate(file_lines, 1) if call_re.search(_code_only(t))]
        if not hits or len(hits) > _CALLSITES_MAX_HITS:
            continue
        taken = 0
        for i in hits:
            if any(s <= i <= e for s, e in fn_spans):
                continue  # the definition itself, or a self-call inside it
            spans.append(_site_span(file_lines, i))
            taken += 1
            if taken >= _CALLSITES_MAX_SITES:
                break
    return spans


# --- model-requested symbols (mode="symbols") -------------------------------
# The escalation ladder answers "unsure?" with "here is a wider blob". This scope
# answers it with "you said you needed `decodeToken`; here it is". The model names
# the identifiers on the previous attempt (classify's `requested_symbols`), and they
# are resolved deterministically here -- no agent, no tool loop, one extra render.

_IDENT_RE = re.compile(r'[A-Za-z_$][\w$]*')
# Lines that look like they DEFINE a name rather than merely mention it.
_DEF_HINT_RE = re.compile(r'\b(?:function|class|const|let|var)\b'
                          r'|[=:]\s*(?:async\s*)?(?:function\b|\()')


def _site_span(file_lines, line_no):
    """Enclosing block of `line_no`, clamped to `_MAX_SITE_SPAN_LINES`.

    A pathological enclosing block (a bundle's module map) degrades to a window
    around the hit rather than swallowing the file.
    """
    lo, hi = _enclosing_block(file_lines, line_no, line_no)
    if hi - lo + 1 > _MAX_SITE_SPAN_LINES:
        half = _MAX_SITE_SPAN_LINES // 2
        return max(1, line_no - half), min(len(file_lines), line_no + half)
    return lo, hi


def _symbol_spans(file_lines, names):
    """Enclosing blocks of the definitions/uses of the identifiers `names`.

    Definition-looking sites are taken first, so a small site budget is spent on
    "where does this come from" rather than on the tenth call.

    Refuses rather than guesses on compressed code: a name shorter than
    `_MIN_IDENT_LEN`, or one occurring on more than `_SYMBOL_MAX_HITS` lines, is a
    minifier alias, and resolving it would return arbitrary parts of the file.
    """
    spans = []
    for raw in list(dict.fromkeys(names or []))[:_SYMBOL_MAX_NAMES]:
        name = str(raw).strip()
        if len(name) < _MIN_IDENT_LEN or not _IDENT_RE.fullmatch(name):
            continue
        word = re.compile(r'\b' + re.escape(name) + r'\b')
        hits = [i for i, t in enumerate(file_lines, 1) if word.search(_code_only(t))]
        if not hits or len(hits) > _SYMBOL_MAX_HITS:
            continue
        hits.sort(key=lambda i: not _DEF_HINT_RE.search(_code_only(file_lines[i - 1])))
        for i in hits[:_SYMBOL_MAX_SITES]:
            spans.append(_site_span(file_lines, i))
    return spans


# --- rank and fill (mode="packed") ------------------------------------------
# Instead of a rung of fixed shape, treat context as a fixed-size suitcase: keep the
# enclosing blocks unconditionally, chunk the rest of the file, rank the chunks by
# how well they match the finding's report, and pack until the budget is spent. A
# prompt over the cap becomes unreachable by construction rather than caught after
# the fact.

def _toks(text):
    """Token estimate, matching llm_client.estimate_token_count."""
    return len(text) // _CHARS_PER_TOKEN


def _line_chars(file_lines):
    """Rendered width of each line, matching _emit_sparse's `NNNN | text` form.

    Budgeting against the RAW source undercounts by the 7-plus characters every
    emitted line carries, which is what let a packed render reach 92_896 tokens
    against a 68_000 cap. Accounting is done in characters and converted once, so
    the sum does not drift the way per-line //3 rounding would.
    """
    return [len(f"{i:4d} | ") + len(t.rstrip()) + 1
            for i, t in enumerate(file_lines, 1)]


# Each kept chunk may introduce one `... N line(s) elided ...` marker; the marker is
# `31 + len(str(gap))` characters, so 34 covers gaps up to 999 lines.
_ELISION_CHARS = 34

# Allowance for a file's `## name (beautified) [partial: N lines total]` heading,
# on top of the filename itself.
_FILE_HEADING_CHARS = 48


def _render_cost(widths, keep, n):
    """Exact rendered width of `keep`, elision markers included.

    Mirrors _emit_sparse rather than approximating it, so the packing loop can be
    checked against what will actually be emitted instead of against an estimate.
    """
    total, prev = 0, None
    for i in sorted(i for i in keep if 1 <= i <= n):
        if prev is not None and i > prev + 1:
            total += _ELISION_CHARS
        total += widths[i - 1]
        prev = i
    return total


def _span_toks(file_lines, lo, hi):
    return _toks("".join(file_lines[lo - 1:hi]))


def _partition(before, after, lo, hi, level):
    """Split [lo, hi] into the brace blocks opening at `level`, and the gaps."""
    parts, run, i = [], None, lo
    while i <= hi:
        if before[i - 1] == level and after[i - 1] > level:
            if run:
                parts.append(run)
                run = None
            j = i
            while j <= hi and after[j - 1] > level:
                j += 1
            end = min(j, hi)
            parts.append((i, end))
            i = end + 1
        else:
            run = (run[0], i) if run else (i, i)
            i += 1
    if run:
        parts.append(run)
    return parts


def _linear_split(file_lines, lo, hi, max_tok):
    """Cut [lo, hi] into ~max_tok pieces by line count alone.

    The fallback for source with no brace structure to descend into -- a data blob,
    or minified code that beautification could not break up. Without it such a file
    is a single unaffordable chunk and `packed` can only take it whole or not at all.
    """
    out, start, acc, cap = [], lo, 0, max_tok * _CHARS_PER_TOKEN
    for i in range(lo, hi + 1):
        acc += len(file_lines[i - 1])
        if acc >= cap and i < hi:
            out.append((start, i))
            start, acc = i + 1, 0
    if start <= hi:
        out.append((start, hi))
    return out


def _chunks(file_lines, before, after, lo, hi, level, max_tok, depth=0):
    """Chop [lo, hi] into pieces of at most `max_tok`, descending into big blocks.

    A webpack bundle is a single depth-0 statement, so a flat split would yield one
    chunk covering the whole file; descending into oversized blocks turns it into one
    chunk per module instead. Where there is no structure left to descend into, the
    span is cut by line count so it stays affordable.
    """
    if _span_toks(file_lines, lo, hi) <= max_tok:
        return [(lo, hi)]
    if depth >= _PACK_MAX_SPLIT_DEPTH:
        return _linear_split(file_lines, lo, hi, max_tok)
    parts = _partition(before, after, lo, hi, level)
    if len(parts) == 1 and parts[0] == (lo, hi):
        if hi - lo < 2:
            return [(lo, hi)]
        inner = _chunks(file_lines, before, after, lo + 1, hi - 1, level + 1,
                        max_tok, depth + 1)
        # Descending bought nothing (no nested block at this level): cut by lines.
        if inner == [(lo + 1, hi - 1)]:
            return _linear_split(file_lines, lo, hi, max_tok)
        return [(lo, lo)] + inner + [(hi, hi)]
    out = []
    for a, b in parts:
        if _span_toks(file_lines, a, b) <= max_tok:
            out.append((a, b))
        else:
            out.extend(_chunks(file_lines, before, after, a, b, level + 1,
                               max_tok, depth + 1))
    return out


def _query_weights(query, file_lines):
    """({identifier: weight}, per-line identifier sets) for ranking chunks.

    Weight falls with how common the identifier is IN THIS FILE, so a name the
    minifier reused everywhere cannot dominate the ranking; identifiers shorter than
    `_MIN_IDENT_LEN` are dropped outright for the same reason.
    """
    terms = {t for t in _IDENT_RE.findall(query or "") if len(t) >= _MIN_IDENT_LEN}
    if not terms:
        return {}, []
    per_line, freq = [], dict.fromkeys(terms, 0)
    for text in file_lines:
        present = terms & set(_IDENT_RE.findall(text))
        per_line.append(present)
        for t in present:
            freq[t] += 1
    n = max(len(file_lines), 1)
    return {t: 1.0 - f / n for t, f in freq.items() if f}, per_line


def _pack_keep(file_lines, mandatory, query, budget):
    """`mandatory` lines plus the best-scoring chunks that still fit `budget`.

    `budget` is in TOKENS of rendered output; the arithmetic below is in characters
    of rendered output and converted once at the boundaries.
    """
    n = len(file_lines)
    widths = _line_chars(file_lines)
    budget_chars = max(0, budget) * _CHARS_PER_TOKEN
    used = sum(widths[i - 1] for i in mandatory if 1 <= i <= n)
    if used >= budget_chars:
        return mandatory

    before, after = _depth_profile(file_lines)
    max_tok = max(400, budget // _PACK_CHUNK_DIVISOR)
    chunks = _chunks(file_lines, before, after, 1, n, 0, max_tok)
    weights, per_line = _query_weights(query, file_lines)

    scored = []
    for lo, hi in chunks:
        if all(i in mandatory for i in range(lo, hi + 1)):
            continue
        score = 0.0
        for i in range(lo, hi + 1):
            for t in (per_line[i - 1] if per_line else ()):
                score += weights.get(t, 0.0)
        cost = sum(widths[i - 1] for i in range(lo, hi + 1)
                   if i not in mandatory) + _ELISION_CHARS
        # Rank by density, not raw score: a small chunk that is entirely on-topic
        # should beat a huge one that merely mentions the same terms once.
        scored.append((score / max(cost, 1), score, lo, hi, cost))
    scored.sort(key=lambda r: (-r[0], -r[1], r[2]))

    keep, added = set(mandatory), []
    for _density, score, lo, hi, cost in scored:
        if score <= 0:
            break              # nothing left that the report actually points at
        if used + cost <= budget_chars:
            keep.update(range(lo, hi + 1))
            added.append((lo, hi))
            used += cost

    # Verify against the real render rather than trusting the running estimate, and
    # give back the least-wanted chunks until it fits. `_chunks` returns a partition,
    # so dropping one cannot remove a line another kept chunk contributed. Without
    # this, accumulated per-chunk rounding put 30/400 packed prompts over the cap.
    while added and _render_cost(widths, keep, n) > budget_chars:
        lo, hi = added.pop()
        keep -= set(range(lo, hi + 1)) - mandatory
    return keep


def canonical_mode(mode, default="lines"):
    """Normalise a configured/requested scope name, resolving pre-26.8 aliases."""
    m = MODE_ALIASES.get(str(mode or "").strip().lower(),
                         str(mode or "").strip().lower())
    return m if m in CONTEXT_MODES else default


def high_tier_base():
    """The scope "toplevel"/"skeleton" keep whole beneath the lines they add.

    config.HIGH_TIER_CONTEXT_BASE, validated. A name outside HIGH_TIER_BASES falls
    back to the default rather than erroring, exactly as `canonical_mode` does for a
    typo'd scope -- a mistyped env line must not silently produce some third
    rendering. Aliases resolve first, so HIGH_TIER_CONTEXT_BASE=function works.
    """
    base = canonical_mode(getattr(config, "HIGH_TIER_CONTEXT_BASE",
                                  _HIGH_TIER_BASE_DEFAULT),
                          default=_HIGH_TIER_BASE_DEFAULT)
    return base if base in HIGH_TIER_BASES else _HIGH_TIER_BASE_DEFAULT


def _scope_spans(file_lines: List[str], line_ranges, mode: str,
                 context_lines: int) -> List[Tuple[int, int]]:
    """The contiguous spans one of "lines"/"block"/"module" keeps, per referenced range.

    Shared by those three scopes' own rendering and by the base of
    "toplevel"/"skeleton", so a high tier's base is literally the same code that
    renders that base as a scope in its own right -- the containment guarantee in the
    module docstring holds by construction rather than by two definitions agreeing.
    """
    if mode == "block":
        return [_enclosing_block(file_lines, s_, e_) for s_, e_ in line_ranges]
    if mode == "module":
        profile = _depth_profile(file_lines)   # once per file, not per range
        return [_enclosing_module(file_lines, s_, e_, profile)
                for s_, e_ in line_ranges]
    return [(max(1, s_ - context_lines), min(len(file_lines), e_ + context_lines))
            for s_, e_ in line_ranges]         # "lines" (original behaviour)


def extract_code_context(ext_dir: Path, line_refs: dict, context_lines: int = 10,
                         mode: str = "lines", all_line_refs: Optional[dict] = None,
                         requested_symbols=None, query: Optional[str] = None,
                         pack_budget: Optional[int] = None) -> str:
    """Extract a beautified source excerpt covering the referenced lines.

    Args:
        ext_dir: Directory containing the extracted extension code.
        line_refs: {filename: [(start_line, end_line), ...]} for the finding(s).
        context_lines: Extra lines before/after each range (mode="lines" only).
        mode: any of CONTEXT_MODES; pre-26.8 aliases accepted (see MODE_ALIASES).
        all_line_refs: whole-report refs; used by mode="used" to decide which
            files to include in full. Falls back to `line_refs` when not given.
        requested_symbols: identifiers the model asked for (mode="symbols").
        query: the finding's report text, used to rank chunks (mode="packed").
        pack_budget: token budget for mode="packed".

    A scope that needs more than the file and the refs degrades to "block" rather
    than erroring -- `symbols` with nothing requested (or nothing resolvable) and
    `packed` with no budget both say so in the header, so a run cannot silently
    believe it escalated.

    Returns:
        Formatted, beautified code excerpt (empty string if nothing to show).
    """
    mode = canonical_mode(mode)
    degraded = ""
    if mode == "symbols" and not requested_symbols:
        mode, degraded = "block", " [symbols: none requested -> enclosing blocks]"
    if mode == "packed" and not pack_budget:
        mode, degraded = "block", " [packed: no budget -> enclosing blocks]"

    refs = all_line_refs if (mode == "used" and all_line_refs) else line_refs
    if not refs:
        return ""

    header = {
        "block": "# ORIGINAL EXTENSION CODE (enclosing blocks)\n",
        "callsites": "# ORIGINAL EXTENSION CODE (enclosing blocks + call sites of their"
                     " names; gaps marked)\n",
        "symbols": "# ORIGINAL EXTENSION CODE (enclosing blocks + the symbols you asked"
                   " for; gaps marked)\n",
        "module": "# ORIGINAL EXTENSION CODE (enclosing bundler modules)\n",
        "toplevel": "# ORIGINAL EXTENSION CODE ({base} + file top level;"
                    " gaps marked)\n",
        "skeleton": "# ORIGINAL EXTENSION CODE ({base} + file top level +"
                    " function signatures; gaps marked)\n",
        "packed": "# ORIGINAL EXTENSION CODE (enclosing blocks + the most relevant"
                  " parts of the file that fit; gaps marked)\n",
        "file": "# ORIGINAL EXTENSION CODE (full files)\n",
        "used": "# ORIGINAL EXTENSION CODE (all referenced files, full)\n",
    }.get(mode, "# ORIGINAL EXTENSION CODE\n")
    tier_base = high_tier_base() if mode in HIGH_TIER_MODES else ""
    if tier_base:
        header = header.replace("{base}", _HIGH_TIER_BASE_LABEL[tier_base])
    output = [header.rstrip("\n") + degraded + "\n"]

    # `packed` spends ONE budget across every file of the finding, so the mandatory
    # blocks are collected for all of them before any optional chunk is bought.
    # Everything here is in RENDERED characters: the per-file elision markers and
    # `## name` headers are part of what the prompt pays for, and deducting only raw
    # line widths let a 3-file finding overshoot its budget by 1_647 tokens.
    loaded_files, mandatory = {}, {}
    pack_remaining = 0            # chars of OPTIONAL content still affordable
    if mode == "packed":
        for filename, line_ranges in sorted(refs.items()):
            if not line_ranges:
                continue
            loaded = _load_file_lines(ext_dir, filename)
            if loaded is None:
                continue
            loaded_files[filename] = loaded
            mandatory[filename] = {i for s_, e_ in
                                   (_enclosing_block(loaded[0], s_, e_)
                                    for s_, e_ in line_ranges)
                                   for i in range(s_, e_ + 1)}
        fixed = len(output[0])
        for f, m in mandatory.items():
            flines = loaded_files[f][0]
            fixed += _render_cost(_line_chars(flines), m, len(flines))
            fixed += len(f) + _FILE_HEADING_CHARS
        pack_remaining = max(0, max(0, pack_budget) * _CHARS_PER_TOKEN - fixed)

    for filename, line_ranges in sorted(refs.items()):
        # For whole-file modes an empty range list still means "this file is
        # referenced" (some adapters register the file with no explicit ranges).
        if not line_ranges and mode not in ("file", "used"):
            continue

        loaded = loaded_files.get(filename) or _load_file_lines(ext_dir, filename)
        if loaded is None:
            continue
        file_lines, beautified = loaded

        suffix = {
            "file": " (beautified, full file)" if beautified else " (full file)",
            "used": " (beautified, full file)" if beautified else " (full file)",
        }.get(mode, " (beautified)" if beautified else "")
        if mode in SPARSE_MODES:
            suffix += f" [partial: {len(file_lines)} lines total]"
        output.append(f"\n## {filename}{suffix}\n")

        if mode in ("file", "used"):
            _emit(output, file_lines, [(1, len(file_lines))])
            continue

        if mode in SPARSE_MODES:
            blocks = [_enclosing_block(file_lines, s_, e_) for s_, e_ in line_ranges]
            keep = {i for s_, e_ in blocks for i in range(s_, e_ + 1)}
            if mode == "callsites":
                for s_, e_ in _callsite_spans(file_lines, blocks):
                    keep.update(range(s_, e_ + 1))
            elif mode == "symbols":
                for s_, e_ in _symbol_spans(file_lines, requested_symbols):
                    keep.update(range(s_, e_ + 1))
            elif mode == "packed":
                # Each file may spend whatever the mandatory blocks left over, and a
                # file that underspends leaves the remainder to the next one. Both
                # sides are measured with _render_cost, so what is deducted is what
                # the prompt is actually charged.
                widths = _line_chars(file_lines)
                nlines = len(file_lines)
                base = _render_cost(widths, keep, nlines)
                keep = _pack_keep(file_lines, keep, query,
                                  (base + pack_remaining) // _CHARS_PER_TOKEN)
                pack_remaining = max(
                    0, pack_remaining - (_render_cost(widths, keep, nlines) - base))
            else:
                # "toplevel"/"skeleton". The base kept whole is configurable; only
                # recompute when it is not the "block" already in `keep`, so the
                # pre-09-03 rendering stays byte-identical under base="block".
                if tier_base != "block":
                    keep = {i for s_, e_ in _scope_spans(file_lines, line_ranges,
                                                         tier_base, context_lines)
                            for i in range(s_, e_ + 1)}
                keep |= _toplevel_lines(file_lines)
                if mode == "skeleton":
                    keep |= {i for i, t in enumerate(file_lines, 1)
                             if _looks_like_function(t)}
            _emit_sparse(output, file_lines, keep)
            continue

        _emit(output, file_lines,
              _merge_ranges(_scope_spans(file_lines, line_ranges, mode, context_lines)))

    return "".join(output)
