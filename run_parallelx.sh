#!/usr/bin/env bash
#
# run_parallelx.sh - run_parallel.sh plus attempt-based retries.
#
# Same sharded verifier as run_parallel.sh, with a retry loop on top. Every launch
# is an ATTEMPT; attempt shards are named <prefix>_<attempt>_<NNN> and each attempt
# writes <run>/attemptN.json holding the stats for that step AND the cumulative
# stats over every attempt so far, at both extension and vulnerability level.
#
# Attempts are never replaced. A finding detected in ANY attempt counts as
# detected in the cumulative view, so retrying can only add. That is a best-of-N
# protocol: report the single-attempt number when you need a clean rate, and the
# cumulative one when you want maximum recall. attemptN.json carries both.
#
# QUICK START
#   ./run_parallelx.sh all   --src DIR --shards 100
#   ./run_parallelx.sh retry --run verification_full_canonical -n 2 --shards 8
#   ./run_parallelx.sh retry --run verification_full_canonical -n 2 --shards 8 --error-only
#   ./run_parallelx.sh retry --run verification_full_canonical -n 2 --shards 8 --failed-only
#   ./run_parallelx.sh retry --run RUN -n 2 --shards 8 --failed-only --include-verified-ext
#   ./run_parallelx.sh status --run verification_full_canonical
#
# SUBCOMMANDS
#   all      stage every eligible extension, run it as attempt 0, write attempt0.json
#   retry    re-run extensions that still have undetected findings, -n times
#   status   backfill any missing attemptN.json and print the cumulative stats
#   score    print cumulative stats for a run (alias of status without backfill)
#   stop     stop every container of a run (Ctrl-C does the same from the foreground)
#
# CONTINUING A RUN
#   'retry --run X' works on runs made by run_parallel.sh too. Shards whose name has
#   no attempt component count as attempt 0, and their attempt0.json is generated
#   retroactively before the first retry.
#   The host --src / --dataset used by a run are recorded as comments in
#   ~/verifier/.env.<run> and reused automatically on continuation; pass --src to override.
#
# SELECTION (what a retry picks up)
#   default              extensions whose cumulative status is failed OR error
#   --error-only         only error
#   --failed-only        only failed
#   --include-verified-ext   also verified extensions that still have undetected findings
#   In every mode an extension is skipped once all of its findings are detected.
#
# OPTIONS (defaults are the canonical configuration)
#   --run NAME | --out NAME   run directory under ~/verifier      (required for retry)
#   -n, --retries N           retry attempts to run. With 'retry' it defaults to 1;
#                             with 'all' it defaults to 0, so 'all -n 2' does the
#                             initial pass and then two retries in one invocation.
#   --retry-shards N          shards for retries launched by 'all'          (8)
#                             Retries want FEW shards: at 100 the cold-container cost
#                             dominates, and 8 recovered 269 -> 14 page_load_failed.
#   --shards N                shards per attempt                  (100)
#   --prefix P                shard prefix; default is the next free letter (a..z, aa..)
#   --timeout SEC             PER_EXTENSION_TIMEOUT               (600)
#   --spoof BOOL              ENABLE_DOMAIN_SPOOFING              (true)
#   --extra-verify-apis CSV   EXTRA_VERIFY_APIS                   (all)
#   --verify-downloads BOOL   VERIFY_DOWNLOADS                    (true)
#   --storage-poll BOOL       STORAGE_POLL                        (true)
#   --web-storage-page-origin BOOL                                (true)
#   --artifacts BOOL          CAPTURE_FAILURE_ARTIFACTS           (false)
#   --payload-timeout SEC     PAYLOAD_EXECUTION_TIMEOUT           (unset)
#   --category CSV            vuln categories, none = all         (none)
#   --max-vulns N|none        per-extension cap                   (none)
#   --sample N|all            'all' only                          (all)
#   --src DIR                 dir of analyzer *_result.json
#   --dataset DIR             dir of <ext_id>.crx                 (/home/gobbi/experiment/DATASET)
#   --chrome PATH             chrome binary, CONTAINER path
#   --image NAME              docker image                        (verify-ext-$USER)
#   --silent                  do not print per-shard progress
#   --poll SEC                progress interval                   (30)
#   --stall SEC               stop a shard whose LAST RESULT is this old, 0 disables
#                             (default: --timeout + 120, i.e. one per-extension budget
#                             plus margin; measured max healthy gap is 603s at 600s)
#   --dry-run                 stage and print the plan, launch nothing
#
# NOTES
#   * Your home is mounted at /work, so ~/verifier -> /work/verifier in the container.
#   * A stalled shard is stopped, not lost: everything it wrote stays, and the next
#     attempt picks up whatever it did not finish.
#   * Run one experiment at a time; the wait loop matches containers by name.

set -euo pipefail
SELF="$(basename "${BASH_SOURCE[0]}")"

# ---- defaults: the canonical configuration --------------------------------
IMAGE="verify-ext-${USER}"
SHARDS=100
RETRY_SHARDS=""
TIMEOUT=600
OUT=""
CATEGORY="none"
MAXV="none"
SAMPLE="all"
ARTIFACTS="false"
PAYLOAD_TIMEOUT=""
STORAGE_POLL="true"
EXTRA_VERIFY="all"
WEBSTORE_PAGE="true"
SPOOF="true"
VERIFY_DL="true"
SRC=""
DATASET="/home/gobbi/experiment/DATASET"
CHROME="/work/chrome-126/chrome-linux64/chrome"
RETRIES=""
SELECT_MODE="both"
INCLUDE_VERIFIED=0
SILENT=0
POLL=30
STALL=""
PREFIX=""
DRY=0

VER_HOST="${HOME}/verifier"
ANA_HOST="${VER_HOST}/analysis"
CODE_HOST="${VER_HOST}/extension_code"
VROOT="/work/verifier"

die()  { echo "error: $*" >&2; exit 1; }
note() { [ "$SILENT" -eq 1 ] || echo "$@"; }
usage() { sed -n '2,95p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# ---- args -----------------------------------------------------------------
CMD="all"
if [ $# -gt 0 ]; then
  case "$1" in
    all|retry|status|score|stop) CMD="$1"; shift;;
    -h|--help|help) usage 0;;
  esac
fi
while [ $# -gt 0 ]; do
  case "$1" in
    --run|--out) OUT="$2"; shift 2;;
    -n|--retries) RETRIES="$2"; shift 2;;
    --shards) SHARDS="$2"; shift 2;;
    --retry-shards) RETRY_SHARDS="$2"; shift 2;;
    --prefix) PREFIX="$2"; shift 2;;
    --timeout) TIMEOUT="$2"; shift 2;;
    --spoof) SPOOF="$2"; shift 2;;
    --extra-verify-apis) EXTRA_VERIFY="$2"; shift 2;;
    --verify-downloads) VERIFY_DL="$2"; shift 2;;
    --storage-poll) STORAGE_POLL="$2"; shift 2;;
    --web-storage-page-origin) WEBSTORE_PAGE="$2"; shift 2;;
    --artifacts) ARTIFACTS="$2"; shift 2;;
    --payload-timeout) PAYLOAD_TIMEOUT="$2"; shift 2;;
    --category) CATEGORY="$2"; shift 2;;
    --max-vulns) MAXV="$2"; shift 2;;
    --sample) SAMPLE="$2"; shift 2;;
    --src) SRC="$2"; shift 2;;
    --dataset) DATASET="$2"; shift 2;;
    --chrome) CHROME="$2"; shift 2;;
    --image) IMAGE="$2"; shift 2;;
    --error-only) SELECT_MODE="error"; shift;;
    --failed-only) SELECT_MODE="failed"; shift;;
    --include-verified-ext) INCLUDE_VERIFIED=1; shift;;
    --silent) SILENT=1; shift;;
    --poll) POLL="$2"; shift 2;;
    --stall) STALL="$2"; shift 2;;
    --dry-run) DRY=1; shift;;
    -h|--help) usage 0;;
    *) die "unknown option: $1";;
  esac
done
[ -n "$OUT" ] || die "--run/--out is required"
if [ -z "$RETRIES" ]; then [ "$CMD" = "retry" ] && RETRIES=1 || RETRIES=0; fi
[ -n "$RETRY_SHARDS" ] || RETRY_SHARDS=8
if [ -z "$STALL" ]; then STALL=$((TIMEOUT + 120)); fi
if [ "$STALL" -gt 0 ] && [ "$STALL" -le "$TIMEOUT" ]; then
  echo "warning: --stall $STALL is not above --timeout $TIMEOUT; a slow-but-healthy extension" >&2
  echo "         can legitimately occupy the full budget, so shards will be stopped for no reason." >&2
fi
RUN_HOST="${VER_HOST}/${OUT}"
ENVFILE="${VER_HOST}/.env.${OUT}"

# ---- python helper --------------------------------------------------------
HELPER="$(mktemp "${TMPDIR:-/tmp}/rpx_helper_XXXXXX.py")"
trap 'rm -f "$HELPER"' EXIT
cat > "$HELPER" <<'PY'
import collections, json, re, shutil, sys
from pathlib import Path

FENCE = chr(96) * 3
ATT = re.compile(r"^[a-z]+_([0-9]+)_[0-9]+$")
RANK = {"verified": 3, "failed": 2, "error": 1, "skipped": 0}


def attempt_of(name):
    m = ATT.match(name)
    return int(m.group(1)) if m else 0


def load_run(rundir):
    """{attempt: {ext_id: record}} over every shard directory in the run."""
    out = collections.defaultdict(dict)
    rd = Path(rundir)
    if not rd.exists():
        return out
    for shard in sorted(p for p in rd.iterdir() if p.is_dir()):
        res = shard / "results"
        if not res.exists():
            continue
        a = attempt_of(shard.name)
        for f in res.rglob("*_result.json"):
            try:
                d = json.load(open(f))
            except Exception:
                continue
            e = d.get("extension_id")
            if e:
                out[a][e] = d
    return out


def merge(byatt, upto=None):
    """Best-of across attempts: an extension keeps its best status, a finding
    counts as detected if any attempt detected it."""
    exts, vul = {}, {}
    for a in sorted(byatt):
        if upto is not None and a > upto:
            continue
        for e, d in byatt[a].items():
            st = d.get("status")
            if e not in exts or RANK.get(st, -1) > RANK.get(exts[e], -1):
                exts[e] = st
            for i, v in enumerate(d.get("vulnerabilities_verified") or []):
                k = (e, v.get("rule_id"), i)
                det = bool(v.get("detection"))
                cur = vul.get(k)
                if cur is None:
                    vul[k] = {"cat": v.get("vulnerability_category"), "det": det,
                              "reason": v.get("failure_reason"),
                              "vstatus": v.get("verification_status")}
                elif det and not cur["det"]:
                    cur.update({"det": True, "reason": None,
                                "vstatus": v.get("verification_status")})
                elif not cur["det"]:
                    cur["reason"] = v.get("failure_reason") or cur["reason"]
                    cur["vstatus"] = v.get("verification_status") or cur["vstatus"]
    return exts, vul


def stats(exts, vul):
    det = sum(1 for v in vul.values() if v["det"])
    ed = {k[0] for k, v in vul.items() if v["det"]}
    cat, catd = collections.Counter(), collections.Counter()
    reason, vst = collections.Counter(), collections.Counter()
    for v in vul.values():
        cat[v["cat"]] += 1
        if v["det"]:
            catd[v["cat"]] += 1
        else:
            reason[v["reason"] or "-"] += 1
            vst[v["vstatus"] or "-"] += 1
    pct = lambda a, b: round(100.0 * a / b, 2) if b else 0.0
    return {
        "extensions": {
            "total": len(exts), "with_detection": len(ed),
            "rate": pct(len(ed), len(exts)),
            "status": dict(collections.Counter(exts.values())),
        },
        "vulnerabilities": {
            "total": len(vul), "detected": det, "rate": pct(det, len(vul)),
            "by_category": {c: {"detected": catd.get(c, 0), "total": n,
                                "rate": pct(catd.get(c, 0), n)}
                            for c, n in cat.most_common()},
            "failure_reasons": dict(reason.most_common()),
            "verification_status": dict(vst.most_common()),
        },
    }


def staged_ids(rundir):
    out = set()
    for f in Path(rundir).glob("staged_attempt*.txt"):
        for line in open(f):
            line = line.strip()
            if line:
                out.add(line)
    return out


def candidates(rundir, mode, include_verified):
    exts, vul = merge(load_run(rundir))
    undet = collections.Counter()
    for k, v in vul.items():
        if not v["det"]:
            undet[k[0]] += 1
    out = []
    for e, st in exts.items():
        if undet.get(e, 0) == 0:
            continue
        if st in ("failed", "error"):
            if mode == "both" or mode == st:
                out.append(e)
        elif st == "verified" and include_verified:
            out.append(e)
    # staged but never wrote a result: no status to match on, always retry
    out.extend(staged_ids(rundir) - set(exts))
    return sorted(set(out))


def stage(src, ana, prefix, attempt, shards, ids, manifest=None):
    src, ana = Path(src), Path(ana)
    made = []
    for i in range(shards):
        d = ana / ("%s_%d_%03d" % (prefix, attempt, i))
        if d.exists():
            shutil.rmtree(d)
        d.mkdir(parents=True)
        made.append(d)
    n, missing = 0, []
    for k, e in enumerate(ids):
        f = src / (e + "_result.json")
        if not f.exists():
            missing.append(e)
            continue
        shutil.copy2(f, made[k % shards] / (e + "_result.json"))
        n += 1
    kept = []
    for d in made:
        if any(d.glob("*_result.json")):
            kept.append(d.name)
        else:
            d.rmdir()
    if manifest:
        gone = set(missing)
        Path(manifest).write_text("\n".join(e for e in ids if e not in gone) + "\n")
    return n, missing, kept


def eligible(src, dataset, category):
    cats = None if category.lower() in ("none", "", "all") else {
        c.strip() for c in category.split(",") if c.strip()}
    ds = Path(dataset)
    out = []
    for f in sorted(Path(src).glob("*_result.json")):
        try:
            s = open(f, encoding="utf-8").read().strip()
            if not s:
                continue
            if s.startswith(FENCE):
                s = s[s.find("\n") + 1:s.rfind(FENCE)]
            d = json.loads(s)
        except Exception:
            continue
        if not any(v.get("result") == "TP"
                   and v.get("attacker_source") in ("Website", "Extension")
                   and (cats is None or v.get("vulnerability_category") in cats)
                   for v in d.get("vulnerabilities", [])):
            continue
        e = d.get("extension_id") or f.name[:-len("_result.json")]
        if (ds / (e + ".crx")).exists():
            out.append(e)
    return out


def write_attempt(rundir, n, meta):
    byatt = load_run(rundir)
    step_e, step_v = merge({n: byatt.get(n, {})})
    prev_e, prev_v = merge({a: v for a, v in byatt.items() if a < n})
    all_e, all_v = merge(byatt, upto=n)
    new_v = sum(1 for k, v in all_v.items()
                if v["det"] and not (prev_v.get(k) or {}).get("det"))
    prev_ok = {e for e, s in prev_e.items() if s == "verified"}
    new_e = len({e for e, s in all_e.items() if s == "verified"} - prev_ok)
    doc = {"attempt": n, "meta": meta,
           "step": stats(step_e, step_v),
           "overall": stats(all_e, all_v),
           "new_in_this_attempt": {"vulnerabilities_detected": new_v,
                                   "extensions_newly_verified": new_e},
           "staged_without_result": sorted(staged_ids(rundir) - set(all_e))}
    (Path(rundir) / ("attempt%d.json" % n)).write_text(json.dumps(doc, indent=2))
    return doc


def show(doc, header):
    s, o = doc["step"], doc["overall"]
    print("\n=== %s ===" % header)
    for lab, b in (("this attempt", s), ("cumulative ", o)):
        e, v = b["extensions"], b["vulnerabilities"]
        print("  %s  extensions %d/%d = %.1f%%   findings %d/%d = %.1f%%   %s"
              % (lab, e["with_detection"], e["total"], e["rate"],
                 v["detected"], v["total"], v["rate"], e["status"]))
    n = doc["new_in_this_attempt"]
    print("  new this attempt: %d findings, %d extensions newly verified"
          % (n["vulnerabilities_detected"], n["extensions_newly_verified"]))
    sw = doc.get("staged_without_result") or []
    if sw:
        print("  WARNING: %d staged extensions produced no result at all "
              "(a shard died); the next retry will pick them up" % len(sw))
    cat = o["vulnerabilities"]["by_category"]
    if cat:
        print("  cumulative by category:")
        for c, b in cat.items():
            print("     %-18s %5d/%-5d = %5.1f%%" % (c, b["detected"], b["total"], b["rate"]))
    fr = list(o["vulnerabilities"]["failure_reasons"].items())[:6]
    if fr:
        print("  top failure reasons: " + ", ".join("%s=%d" % (k, n) for k, n in fr))


cmd = sys.argv[1]
if cmd == "attempts":
    print(" ".join(str(a) for a in sorted(load_run(sys.argv[2]))))
elif cmd == "candidates":
    print("\n".join(candidates(sys.argv[2], sys.argv[3], sys.argv[4] == "1")))
elif cmd == "eligible":
    print("\n".join(eligible(sys.argv[2], sys.argv[3], sys.argv[4])))
elif cmd == "stage":
    ids = [x.strip() for x in open(sys.argv[7]) if x.strip()]
    n, missing, kept = stage(sys.argv[2], sys.argv[3], sys.argv[4],
                             int(sys.argv[5]), int(sys.argv[6]), ids,
                             sys.argv[8] if len(sys.argv) > 8 else None)
    print("%d\n%d\n%s" % (n, len(missing), " ".join(kept)))
elif cmd == "write":
    meta = json.load(open(sys.argv[4])) if len(sys.argv) > 4 else {}
    show(write_attempt(sys.argv[2], int(sys.argv[3]), meta),
         "attempt %s" % sys.argv[3])
elif cmd == "backfill":
    rundir = sys.argv[2]
    for a in sorted(load_run(rundir)):
        p = Path(rundir) / ("attempt%d.json" % a)
        if not p.exists():
            write_attempt(rundir, a, {"backfilled": True})
            print("  wrote %s" % p.name)
elif cmd == "report":
    rundir = sys.argv[2]
    atts = sorted(load_run(rundir))
    if not atts:
        print("no results under %s" % rundir)
    else:
        last = atts[-1]
        p = Path(rundir) / ("attempt%d.json" % last)
        doc = json.load(open(p)) if p.exists() else write_attempt(rundir, last, {})
        show(doc, "%s (attempts: %s)" % (Path(rundir).name,
                                         ", ".join(str(a) for a in atts)))
PY

py() { python3 "$HELPER" "$@"; }

# Containers are detached, so the shell dying does not stop them. Ctrl-C must.
live_ids() { docker ps -q --filter "name=vext_${OUT}_" 2>/dev/null || true; }
stop_run() {
  local ids; ids="$(live_ids)"
  [ -n "$ids" ] && echo "$ids" | xargs -r docker stop >/dev/null 2>&1 || true
}
on_int() {
  trap - INT TERM
  echo
  echo ">> interrupted - stopping $(live_ids | wc -l) container(s) of run $OUT"
  stop_run
  echo ">> every result already written is kept. pick up where it stopped with:"
  echo "     $SELF retry --run $OUT -n 1 --shards 8"
  exit 130
}
trap on_int INT TERM

# ---- env file: canonical settings plus the host paths ---------------------
write_env() {
  mkdir -p "$(dirname "$ENVFILE")"
  cat > "$ENVFILE" <<EOF
EXTENSION_CODE_DIR=${VROOT}/extension_code
RESULTS_ANALYSIS_DIR=${VROOT}/analysis
RESULTS_VERIFICATION_DIR=${VROOT}/${OUT}
USE_LOCAL_VERIFICATION_SERVER=true
CHROME_BINARY_PATH=${CHROME}
VERIFIER_FILTER_VULNERABILITY_CATEGORIES=${CATEGORY}
VERIFIER_FILTER_STORAGE_APIS=none
VERIFIER_FILTER_MIN_VULNERABILITIES=none
VERIFIER_FILTER_MAX_VULNERABILITIES=${MAXV}
PER_EXTENSION_TIMEOUT=${TIMEOUT}
ENABLE_DOMAIN_SPOOFING=${SPOOF}
CAPTURE_FAILURE_ARTIFACTS=${ARTIFACTS}
SPOOF_CERT_DIR=/tmp/spoof_certs
EOF
  [ -n "$PAYLOAD_TIMEOUT" ] && echo "PAYLOAD_EXECUTION_TIMEOUT=${PAYLOAD_TIMEOUT}" >> "$ENVFILE"
  [ "$STORAGE_POLL"  = "true" ] && echo "STORAGE_POLL=true" >> "$ENVFILE"
  [ "$WEBSTORE_PAGE" = "true" ] && echo "WEB_STORAGE_PAGE_ORIGIN=true" >> "$ENVFILE"
  [ "$VERIFY_DL"     = "true" ] && echo "VERIFY_DOWNLOADS=true" >> "$ENVFILE"
  [ -n "$EXTRA_VERIFY" ] && echo "EXTRA_VERIFY_APIS=${EXTRA_VERIFY}" >> "$ENVFILE"
  # host-side provenance; docker --env-file ignores comment lines
  {
    echo "#X_SRC=${SRC}"
    echo "#X_DATASET=${DATASET}"
    echo "#X_IMAGE=${IMAGE}"
  } >> "$ENVFILE"
  return 0
}

read_env_path() {  # $1 = key, echoes the recorded value or nothing
  [ -f "$ENVFILE" ] || return 0
  sed -n "s/^#$1=//p" "$ENVFILE" | tail -1
}

# ---- next free prefix (a..z, aa..zz), unused in analysis/ and the run ------
next_prefix() {
  local a b p
  for a in "" a b c d e f g h i j k l m n o p q r s t u v w x y z; do
    for b in a b c d e f g h i j k l m n o p q r s t u v w x y z; do
      p="${a}${b}"
      compgen -G "${ANA_HOST}/${p}_*" >/dev/null 2>&1 && continue
      compgen -G "${RUN_HOST}/${p}_*" >/dev/null 2>&1 && continue
      echo "$p"; return 0
    done
  done
  die "no free prefix left"
}

# ---- launch one attempt ---------------------------------------------------
launch() {  # $1 = space separated shard names, $2 = expected extension count
  local names="$1" expected="$2" name
  local total launched start
  total=$(echo $names | wc -w)
  launched=0
  start=$(date +%s)
  # 'docker run -d' costs several seconds each on a busy daemon, so a 100-shard
  # launch takes minutes. Narrate it, or the run looks hung before it starts.
  for name in $names; do
    docker run --rm -d --name "vext_${OUT}_${name}" \
      -v "${HOME}:/work" -u "$(id -u):$(id -g)" -e HOME=/tmp \
      --env-file "$ENVFILE" -e "RESULTS_TO_VERIFY=${name}" \
      --shm-size=2g "$IMAGE" > /dev/null
    launched=$((launched + 1))
    if [ "$SILENT" -eq 0 ] && { [ $((launched % 10)) -eq 0 ] || [ "$launched" -eq 1 ] || [ "$launched" -eq "$total" ]; }; then
      printf '%s  launching %d/%d  (%d done, %d running)\n' "$(date +%H:%M:%S)" \
        "$launched" "$total" "$(find "${RUN_HOST}" -name '"'"'*_result.json'"'"' 2>/dev/null | wc -l)" \
        "$(live_ids | wc -l)"
    fi
  done
  while [ "$(docker ps -q --filter "name=vext_${OUT}_" | wc -l)" -gt 0 ]; do
    if [ "$SILENT" -eq 0 ]; then
      local done_n live line d n busy
      done_n=0; line=""
      for d in $names; do
        n=$(ls "${RUN_HOST}/${d}/results" 2>/dev/null | wc -l)
        done_n=$((done_n + n))
        [ "$total" -le 24 ] && line="${line} ${n}"
      done
      live=$(live_ids | wc -l)
      if [ "$total" -gt 24 ]; then
        # only the shards still working are interesting once there are many
        busy=""
        for d in $(docker ps --filter "name=vext_${OUT}_" --format '{{.Names}}' 2>/dev/null | sed "s/^vext_${OUT}_//" | head -8); do
          busy="${busy} ${d}=$(ls "${RUN_HOST}/${d}/results" 2>/dev/null | wc -l)"
        done
        line="$busy"
      fi
      printf '%s  %d/%d  containers=%s  running:%s\n' \
        "$(date +%H:%M:%S)" "$done_n" "$expected" "$live" "$line"
    fi
    if [ "$STALL" -gt 0 ]; then
      for d in $names; do
        docker ps -q --filter "name=^vext_${OUT}_${d}$" | grep -q . || continue
        local newest idle base
        newest=$(find "${RUN_HOST}/${d}/results" -name '*_result.json' -printf '%T@\n' 2>/dev/null | sort -n | tail -1)
        # No result yet means it is still on its FIRST extension - measure from launch,
        # otherwise a shard that hangs immediately would never be caught.
        if [ -z "$newest" ]; then base="$start"; else base="${newest%.*}"; fi
        idle=$(( $(date +%s) - base ))
        if [ "$idle" -gt "$STALL" ]; then
          echo "  STALL ${d} idle ${idle}s -> stopping (its results are kept; the next attempt picks up the rest)"
          docker stop "vext_${OUT}_${d}" >/dev/null 2>&1 || true
        fi
      done
    fi
    sleep "$POLL"
  done
  note ">> attempt finished in $(( ($(date +%s) - start) / 60 )) min (launch included)"
}

run_attempt() {  # $1 = attempt number, $2 = ids file, $3 = label
  local att="$1" idsfile="$2" label="$3" pfx n
  n=$(grep -c . "$idsfile" || true)
  [ "$n" -gt 0 ] || { note ">> nothing to do for $label"; return 1; }
  pfx="${PREFIX:-$(next_prefix)}"
  mkdir -p "$ANA_HOST" "$CODE_HOST" "$RUN_HOST"
  local out kept staged missing
  mkdir -p "$RUN_HOST"
  out=$(py stage "$SRC" "$ANA_HOST" "$pfx" "$att" "$SHARDS" "$idsfile" "${RUN_HOST}/staged_attempt${att}.txt")
  staged=$(echo "$out" | sed -n 1p); missing=$(echo "$out" | sed -n 2p); kept=$(echo "$out" | sed -n 3p)
  note ">> attempt $att ($label): $staged extensions, prefix $pfx, $(echo $kept | wc -w) shards$([ "$missing" -gt 0 ] && echo ", $missing missing from --src")"
  write_env
  if [ "$DRY" -eq 1 ]; then
    note "   --dry-run: staged only. shards: $kept"
    return 0
  fi
  launch "$kept" "$staged"
  local meta; meta="$(mktemp)"
  printf '{"prefix":"%s","shards":%s,"selection":"%s","include_verified_ext":%s,"src":"%s","timeout":%s,"spoof":"%s","extra_verify_apis":"%s","verify_downloads":"%s","storage_poll":"%s","web_storage_page_origin":"%s","staged":%s}' \
    "$pfx" "$SHARDS" "$label" "$INCLUDE_VERIFIED" "$SRC" "$TIMEOUT" "$SPOOF" \
    "$EXTRA_VERIFY" "$VERIFY_DL" "$STORAGE_POLL" "$WEBSTORE_PAGE" "$staged" > "$meta"
  py write "$RUN_HOST" "$att" "$meta"
  rm -f "$meta"
  return 0
}

do_retries() {  # $1 = highest attempt number already present
  local last="$1" i=0 ids
  ids="$(mktemp)"
  while [ "$i" -lt "$RETRIES" ]; do
    i=$((i + 1)); last=$((last + 1))
    py candidates "$RUN_HOST" "$SELECT_MODE" "$INCLUDE_VERIFIED" > "$ids"
    note ">> retry $i/$RETRIES: $(grep -c . "$ids" || true) extensions selected (mode=$SELECT_MODE include_verified=$INCLUDE_VERIFIED)"
    if ! run_attempt "$last" "$ids" "retry:$SELECT_MODE"; then
      note ">> nothing left to retry"; break
    fi
    [ "$DRY" -eq 1 ] && break
  done
  rm -f "$ids"
  return 0
}

# ---- subcommands ----------------------------------------------------------
case "$CMD" in
  stop)
    n=$(live_ids | wc -l)
    [ "$n" -gt 0 ] || { echo "no containers running for run $OUT"; exit 0; }
    echo ">> stopping $n container(s) of run $OUT"
    stop_run
    echo ">> results already written are kept; resume with: $SELF retry --run $OUT -n 1 --shards 8"
    ;;

  status|score)
    [ -d "$RUN_HOST" ] || die "no such run: $RUN_HOST"
    [ "$CMD" = "status" ] && { note ">> backfilling missing attempt json"; py backfill "$RUN_HOST"; }
    py report "$RUN_HOST"
    ;;

  all)
    [ -n "$SRC" ] || die "--src is required for 'all'"
    [ -d "$SRC" ] || die "no such --src: $SRC"
    [ "$SAMPLE" = "all" ] || die "--sample is not supported; use 'all'"
    ids="$(mktemp)"; trap 'rm -f "$HELPER" "$ids"' EXIT
    note ">> scanning $SRC for eligible extensions"
    py eligible "$SRC" "$DATASET" "$CATEGORY" > "$ids"
    note ">> eligible: $(grep -c . "$ids" || true)"
    run_attempt 0 "$ids" "initial" || true
    if [ "$RETRIES" -gt 0 ] && [ "$DRY" -eq 0 ]; then
      SHARDS="$RETRY_SHARDS"
      note ">> initial pass done; $RETRIES retry attempt(s) at $SHARDS shards"
      do_retries 0
    fi
    ;;

  retry)
    [ -d "$RUN_HOST" ] || die "no such run: $RUN_HOST"
    [ -n "$SRC" ] || SRC="$(read_env_path X_SRC)"
    [ -n "$SRC" ] || die "no --src given and none recorded in $ENVFILE; pass --src"
    [ -d "$SRC" ] || die "recorded --src does not exist: $SRC"
    if [ "$DATASET" = "/home/gobbi/experiment/DATASET" ]; then
      rec="$(read_env_path X_DATASET)"; [ -n "$rec" ] && DATASET="$rec"
    fi
    note ">> run $OUT   src $SRC"
    note ">> backfilling missing attempt json"; py backfill "$RUN_HOST"
    last=$(py attempts "$RUN_HOST" | tr ' ' '\n' | sort -n | tail -1)
    [ -n "$last" ] || die "run has no results to retry"
    do_retries "$last"
    ;;
esac
