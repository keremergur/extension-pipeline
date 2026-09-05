"""
Per-extension candidate prioritisation and cutoff.

CodeQL emits every finding it can prove; the analyzer does not have to spend an
LLM call on all of them. This module decides WHICH of an extension's findings are
worth the money, and how many.

The strategies here are the ones measured offline in EXPERIMENTS.md 56-60 by
replaying runs that analyzed every finding, so the retention numbers quoted in
each docstring are measured, not estimated. Headline results:

  * position carries no signal (the 12th finding of an extension is as likely to
    be a TP as the 1st), so `first_n` is dominated everywhere and is kept only as
    the baseline;
  * `rule_id` carries a lot, and it is known before a token is generated;
  * `mmr` over the rule prior retained 98.4% of verified extensions for 63% of
    the calls, against `first_n`'s 89.4% for the same money.

Every strategy takes the extension's candidate list plus N and returns the
candidates to analyze, in the order to analyze them. N is a hard cap for all of
them EXCEPT n_per_rule / n_per_msg / prop_alloc / log_budget, whose budget is per
rule or per size and can exceed N (see ANALYZER_PRIORITY_N docs in config).
"""

import collections
import json
import math
import os
import random
import re
from typing import Callable, Dict, List, Optional, Sequence

import config

# --------------------------------------------------------------------------
# the yield prior
# --------------------------------------------------------------------------

_PRIOR: Dict[str, float] = {}
_PRIOR_FAMILY: Dict[str, float] = {}
_PRIOR_DEFAULT: float = 0.0
_PRIOR_LOADED = False


def _default_prior_path() -> str:
    """
    Where the shipped rule prior lives. ANALYZER_PRIORITY_PRIOR_FILE wins; failing
    that the file travels with the pipeline, so it is looked for beside src/ and
    inside it. Both are checked because the repo root differs between a Docker
    image (code copied to /app) and a local checkout.
    """
    explicit = getattr(config, 'ANALYZER_PRIORITY_PRIOR_FILE', '')
    if explicit:
        return explicit
    here = os.path.dirname(os.path.abspath(__file__))          # .../src/analyzer
    src = os.path.dirname(here)                                # .../src
    root = os.path.dirname(src)                                # .../extension-pipeline
    for cand in (os.path.join(root, 'rule_prior.json'),
                 os.path.join(src, 'rule_prior.json'),
                 os.path.join(here, 'rule_prior.json')):
        if os.path.exists(cand):
            return cand
    return os.path.join(root, 'rule_prior.json')


def load_prior(path: Optional[str] = None, logger=None) -> bool:
    """
    Load P(verified | rule_id). Ships as rule_prior.json: 49 rules pooled over
    three verifier generations with Beta-Binomial shrinkage, so it works without
    any prior runs on disk. Returns False when unavailable, in which case every
    prior-based strategy degrades to the corpus base rate (i.e. to round_robin).
    """
    global _PRIOR_DEFAULT, _PRIOR_LOADED
    p = path or _default_prior_path()
    try:
        with open(p) as fh:
            d = json.load(fh)
    except Exception as ex:                                       # noqa: BLE001
        if logger:
            logger(f"priority: no rule prior at {p} ({ex.__class__.__name__}); "
                   f"prior-based strategies will fall back to round-robin", "WARNING")
        _PRIOR_LOADED = False
        return False
    _PRIOR.clear()
    _PRIOR.update(d.get('rules', {}))
    _PRIOR_DEFAULT = float(d.get('_base_rate', 0.0))
    fams = collections.defaultdict(list)
    for r, v in _PRIOR.items():
        fams['/'.join(r.split('/')[:-1])].append(v)
    _PRIOR_FAMILY.clear()
    _PRIOR_FAMILY.update({k: sum(v) / len(v) for k, v in fams.items()})
    _PRIOR_LOADED = True
    if logger:
        logger(f"priority: rule prior loaded from {p} "
               f"({len(_PRIOR)} rules, base rate {_PRIOR_DEFAULT:.3f})")
    return True


def prior_of(rule: str) -> float:
    """Rule score, backing off to the rule's family, then the global base rate."""
    if not _PRIOR_LOADED:
        load_prior()
    if rule in _PRIOR:
        return _PRIOR[rule]
    fam = '/'.join(str(rule).split('/')[:-1])
    return _PRIOR_FAMILY.get(fam, _PRIOR_DEFAULT)


# --------------------------------------------------------------------------
# candidate keys
# --------------------------------------------------------------------------

def _rule(c) -> str:
    return getattr(c, 'identifier', None) or ''


def _msg(c) -> str:
    """
    The finding's `message`, which reads "SOURCE <api> & KEY <name>" and is the
    only real dedupe key in the corpus: it collapses 15310 findings to 10736,
    while sink locations are 98.5% distinct and dedupe to nothing. Falls back to
    the candidate's identity so a missing message never merges two findings.
    """
    snip = getattr(c, 'report_snippet', '') or ''
    m = re.search(r'"message"\s*:\s*"((?:[^"\\]|\\.)*)"', snip)
    return m.group(1) if m else f'__nomsg__{id(c)}'


def _screen(c) -> float:
    """Signed screen confidence in [-1, 1]; 0 when the screen has not run."""
    v = getattr(c, 'screen_score', None)
    return 0.0 if v is None else float(v)


# --------------------------------------------------------------------------
# strategies: (candidates, n) -> ordered list of candidates to analyze
# --------------------------------------------------------------------------

def _buckets(cands):
    b = collections.OrderedDict()
    for c in cands:
        b.setdefault(_rule(c), []).append(c)
    return b


def s_all(cands, n):
    """No cutoff. Every finding is analyzed (the pre-existing behaviour)."""
    return list(cands)


def s_first_n(cands, n):
    """The first N as CodeQL emitted them. Baseline; dominated everywhere."""
    return list(cands[:n])


def s_uniq_rule_first(cands, n):
    """One of each rule before a second of any; same cost as first_n, better."""
    seen, head, tail = set(), [], []
    for c in cands:
        (head if _rule(c) not in seen else tail).append(c)
        seen.add(_rule(c))
    return (head + tail)[:n]


def s_round_robin(cands, n):
    """Deal them out one rule at a time until N is spent."""
    queues = list(_buckets(cands).values())
    out = []
    while len(out) < n and any(queues):
        for q in queues:
            if q and len(out) < n:
                out.append(q.pop(0))
    return out


def s_n_per_rule(cands, n):
    """N of every distinct rule. Budget is per rule, so the total can exceed N."""
    seen, out = collections.Counter(), []
    for c in cands:
        if seen[_rule(c)] < n:
            out.append(c)
            seen[_rule(c)] += 1
    return out


def s_n_per_msg(cands, n):
    """N of every distinct (rule, message). Also uncapped in total."""
    seen, out = collections.Counter(), []
    for c in cands:
        k = (_rule(c), _msg(c))
        if seen[k] < n:
            out.append(c)
            seen[k] += 1
    return out


def _dedup_msg(cands):
    seen, out = set(), []
    for c in cands:
        k = (_rule(c), _msg(c))
        if k not in seen:
            seen.add(k)
            out.append(c)
    return out


def s_dedup_msg_first_n(cands, n):
    """Drop repeats of (rule, message), then take the first N survivors."""
    return _dedup_msg(cands)[:n]


def s_dedup_msg_rr(cands, n):
    """Drop those repeats, then deal out one rule at a time."""
    return s_round_robin(_dedup_msg(cands), n)


def s_prop_alloc(cands, n):
    """Each rule gets a share of N proportional to how many findings it has."""
    b = _buckets(cands)
    out = []
    for q in b.values():
        out.extend(q[:max(1, round(n * len(q) / max(1, len(cands))))])
    out.sort(key=lambda c: cands.index(c))
    return out[:max(n, len(b))]


def s_log_budget(cands, n):
    """Budget grows with log2 of the finding count, not linearly."""
    return s_round_robin(cands, n * max(1, math.ceil(math.log2(len(cands) + 1))))


def s_greedy_cover(cands, n):
    """Always take the finding covering the most not-yet-seen features."""
    def feats(c):
        return {('r', _rule(c)), ('m', _rule(c), _msg(c))}
    covered, out, pool = set(), [], list(cands)
    while pool and len(out) < n:
        best = max(pool, key=lambda c: (len(feats(c) - covered), -pool.index(c)))
        out.append(best)
        covered |= feats(best)
        pool.remove(best)
    return out


def s_rule_prior(cands, n):
    """Top N findings by their rule's historical verified-rate."""
    idx = {id(c): i for i, c in enumerate(cands)}
    return sorted(cands, key=lambda c: (-prior_of(_rule(c)), idx[id(c)]))[:n]


def s_prior_rr(cands, n):
    """Round-robin the rules, visiting high-yield rules first."""
    b = _buckets(cands)
    order = sorted(b, key=lambda r: (-prior_of(r), list(b).index(r)))
    queues = [b[r] for r in order]
    out = []
    while len(out) < n and any(queues):
        for q in queues:
            if q and len(out) < n:
                out.append(q.pop(0))
    return out


def s_prior_top_rules(cands, n):
    """One finding from each of the top N rules."""
    b = _buckets(cands)
    order = sorted(b, key=lambda r: (-prior_of(r), list(b).index(r)))
    return [b[r][0] for r in order[:n]]


def s_prior_best_rule(cands, n):
    """N findings from the single best-ranked rule present."""
    b = _buckets(cands)
    best = min(b, key=lambda r: (-prior_of(r), list(b).index(r)))
    return b[best][:n]


def _mmr(cands, n, lam, relevance, per_rule_cap=None):
    kept, rules, msgs = [], set(), set()
    used = collections.Counter()
    pool = list(cands)
    idx = {id(c): i for i, c in enumerate(cands)}
    while pool and len(kept) < n:
        def score(c):
            red = 0.5 * (_rule(c) in rules) + 0.5 * ((_rule(c), _msg(c)) in msgs)
            return lam * relevance(c) - (1 - lam) * red
        cs = [c for c in pool
              if per_rule_cap is None or used[_rule(c)] < per_rule_cap] or pool
        best = max(cs, key=lambda c: (score(c), -idx[id(c)]))
        kept.append(best)
        rules.add(_rule(best))
        msgs.add((_rule(best), _msg(best)))
        used[_rule(best)] += 1
        pool.remove(best)
    return kept


def s_mmr(cands, n):
    """
    Maximal Marginal Relevance over the rule prior: each round take the finding
    with the best (yield minus how much it repeats what is already taken).
    Best rule measured: 98.4% of verified extensions retained at 63% of the calls.
    """
    lam = float(getattr(config, 'ANALYZER_PRIORITY_MMR_LAM', 0.7))
    cap = getattr(config, 'ANALYZER_PRIORITY_MMR_RULE_CAP', 0) or None
    return _mmr(cands, n, lam, lambda c: prior_of(_rule(c)), cap)


def s_thompson(cands, n):
    """Beta-Bernoulli bandit over rules. Matches rule_prior; adds a seed."""
    rng = random.Random(getattr(config, 'ANALYZER_PRIORITY_SEED', 0))
    b = _buckets(cands)
    out = []
    while len(out) < n and any(b.values()):
        live = [r for r, q in b.items() if q]
        draws = {r: rng.betavariate(max(0.05, prior_of(r) * 8),
                                    max(0.05, (1 - prior_of(r)) * 8)) for r in live}
        out.append(b[max(live, key=lambda r: draws[r])].pop(0))
    return out


def s_screen_top(cands, n):
    """Top N by the cheap screen's signed confidence. Needs the screen step."""
    idx = {id(c): i for i, c in enumerate(cands)}
    return sorted(cands, key=lambda c: (-_screen(c), idx[id(c)]))[:n]


def _combined(c):
    w = float(getattr(config, 'ANALYZER_PRIORITY_SCREEN_WEIGHT', 0.5))
    return w * prior_of(_rule(c)) + (1 - w) * (_screen(c) + 1) / 2


def s_prior_screen(cands, n):
    """Half the rule's track record, half what the screen thought of this one."""
    idx = {id(c): i for i, c in enumerate(cands)}
    return sorted(cands, key=lambda c: (-_combined(c), idx[id(c)]))[:n]


def s_prior_screen_mmr(cands, n):
    """
    The combined prior+screen signal with MMR's novelty penalty. Best measured
    option when the screen step is enabled: 98.6% of verified extensions retained
    with zero losses, at 63% of the calls plus roughly 2% for the screen itself.
    """
    lam = float(getattr(config, 'ANALYZER_PRIORITY_MMR_LAM', 0.7))
    cap = getattr(config, 'ANALYZER_PRIORITY_MMR_RULE_CAP', 0) or None
    return _mmr(cands, n, lam, _combined, cap)


STRATEGIES: Dict[str, Callable] = collections.OrderedDict([
    ('all', s_all),
    ('first_n', s_first_n),
    ('uniq_rule_first', s_uniq_rule_first),
    ('round_robin', s_round_robin),
    ('n_per_rule', s_n_per_rule),
    ('n_per_msg', s_n_per_msg),
    ('dedup_msg_first_n', s_dedup_msg_first_n),
    ('dedup_msg_rr', s_dedup_msg_rr),
    ('prop_alloc', s_prop_alloc),
    ('log_budget', s_log_budget),
    ('greedy_cover', s_greedy_cover),
    ('rule_prior', s_rule_prior),
    ('prior_rr', s_prior_rr),
    ('prior_top_rules', s_prior_top_rules),
    ('prior_best_rule', s_prior_best_rule),
    ('mmr', s_mmr),
    ('thompson', s_thompson),
    ('screen_top', s_screen_top),
    ('prior_screen', s_prior_screen),
    ('prior_screen_mmr', s_prior_screen_mmr),
])

#: Strategies whose per-extension total can exceed N.
UNCAPPED = {'n_per_rule', 'n_per_msg', 'prop_alloc', 'log_budget'}

#: Strategies that read candidate.screen_score, so the screen step must run.
NEEDS_SCREEN = {'screen_top', 'prior_screen', 'prior_screen_mmr'}


# --------------------------------------------------------------------------
# corpus-level allocation (not per-extension; used by the scheduler)
# --------------------------------------------------------------------------

def global_greedy(per_ext: Dict[str, Sequence], budget: int) -> Dict[str, list]:
    """
    Spend one pooled budget across the WHOLE corpus instead of N per extension.

    Beats every per-extension rule on verified FINDINGS (82.9% vs 73.4% at the
    same cost) and loses on verified EXTENSIONS (94.9% vs 98.4%), because it
    abandons whole low-yield extensions to buy more findings in rich ones. Use it
    only when the deliverable is a vulnerability count, not an extension count.

    Requires every extension's candidates up front, so it cannot run in the
    streaming scheduler without a pre-pass.
    """
    rows = []
    for eid, cands in per_ext.items():
        for i, c in enumerate(cands):
            rows.append((prior_of(_rule(c)), eid, i, c))
    rows.sort(key=lambda r: -r[0])
    kept: Dict[str, list] = collections.defaultdict(list)
    seen, second, spent = set(), [], 0
    for s, eid, i, c in rows:
        if eid in seen or spent >= budget:
            second.append((s * 0.5, eid, i, c))
            continue
        kept[eid].append(c)
        seen.add(eid)
        spent += 1
    second.sort(key=lambda r: -r[0])
    for s, eid, i, c in second:
        if spent >= budget:
            break
        kept[eid].append(c)
        spent += 1
    return kept


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def select(candidates: List, logger=None) -> List:
    """
    Apply the configured strategy to one extension's candidates.

    Returns the candidates to analyze, in analysis order. With the default
    strategy ("all") the list is returned untouched, so a run made without any
    ANALYZER_PRIORITY_* setting is byte-identical to one made before this existed.
    """
    name = str(getattr(config, 'ANALYZER_PRIORITY_STRATEGY', 'all') or 'all').strip()
    n = int(getattr(config, 'ANALYZER_PRIORITY_N', 0) or 0)
    if name == 'all' or not candidates:
        return list(candidates)
    fn = STRATEGIES.get(name)
    if fn is None:
        if logger:
            logger(f"priority: unknown ANALYZER_PRIORITY_STRATEGY {name!r}; "
                   f"known: {', '.join(STRATEGIES)}. Analyzing everything.", "ERROR")
        return list(candidates)
    if n <= 0:
        if logger:
            logger(f"priority: strategy {name!r} needs ANALYZER_PRIORITY_N > 0; "
                   f"analyzing everything", "WARNING")
        return list(candidates)
    if name in NEEDS_SCREEN and not getattr(config, 'ANALYZER_SCREEN_ENABLED', False):
        if logger:
            logger(f"priority: strategy {name!r} reads the screen score but "
                   f"ANALYZER_SCREEN_ENABLED is off; every score is 0 and the "
                   f"selection collapses to the rule prior", "WARNING")
    kept = fn(list(candidates), n)
    # Never return nothing: an extension with candidates must keep at least one,
    # or it silently disappears from the results instead of being judged.
    if not kept:
        kept = list(candidates[:1])
    if logger and len(kept) < len(candidates):
        logger(f"priority[{name}/N={n}]: {len(kept)}/{len(candidates)} candidates selected")
    return kept
