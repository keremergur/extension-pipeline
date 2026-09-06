#!/usr/bin/env bash
#
# run_parallel.sh — shard the analyzer output and run the extension verifier
# across many Docker containers in parallel, then score the results.
#
# One container processes one shard sequentially; N shards run at once. Each
# container has its own network namespace, so all of them bind 127.0.0.1:3000
# without conflict — parallelism needs no code change, only more shards.
#
# WHY THE 600s DEFAULT: PER_EXTENSION_TIMEOUT is a WALL-CLOCK budget. Under heavy
# parallelism, CPU contention can push a heavy extension (many vulnerabilities)
# past a short budget; it then times out and its findings are recorded as misses,
# so the extension drops out entirely. That makes the detection count depend on
# how parallel the run was ("sequential gives more than parallel"). Measured on
# the heavy tail: at 100 shards a 180s budget dropped 46/799 extensions; a 600s
# budget recovered 45 of them at the same parallelism. So: keep the parallelism,
# give heavy extensions enough wall-clock. Do NOT lower --timeout for a run whose
# numbers you intend to report.
#
# QUICK START (defaults are tuned for this box):
#   ./run_parallel.sh all                      # shard all TP extensions -> 100 shards, run, score
#   ./run_parallel.sh all --shards 100 --timeout 600 --out verification_full
#
# SUBCOMMANDS:
#   shard [opts]        split *_result.json into --shards buckets and stage the .crx files
#   run   [opts]        launch one container per existing shard and wait for completion
#   score DIR [DIR2]    summarize detections in a run (two dirs -> diff them)
#   all   [opts]        shard, then run, then score
#
# OPTIONS (with defaults):
#   --image     NAME    docker image to run                 (verify-ext-$USER)
#   --prefix    STR     shard-name prefix                   (z)
#   --shards    N       number of shards = parallelism      (100)
#   --timeout   SEC     PER_EXTENSION_TIMEOUT (wall-clock)  (600)
#   --out       NAME    output dir name under ~/verifier    (verification)
#   --category  CSV     vuln categories, "none" = all       (none)
#   --max-vulns N|none  per-extension cap                   (none)
#   --sample    N|all   how many extensions to shard        (all)
#   --artifacts BOOL    capture failure artifacts           (true)
#   --payload-timeout SEC  PAYLOAD_EXECUTION_TIMEOUT         (unset -> 3)
#   --storage-poll BOOL    poll the storage read vs single-shot (STORAGE_POLL)  (false)
#   --extra-verify-apis CSV  un-skip APIs: "all" or comma list (EXTRA_VERIFY_APIS)  (unset)
#   --web-storage-page-origin BOOL  read/seed web storage at the page origin (WEB_STORAGE_PAGE_ORIGIN)  (false)
#   --spoof BOOL           domain spoofing: navigate as each finding's specific_domain (ENABLE_DOMAIN_SPOOFING)  (false)
#   --verify-downloads BOOL  detect downloads via chrome.downloads.search outcome (VERIFY_DOWNLOADS)  (false)
#   --src       DIR     source dir of *_result.json         (~/verifier/analysis/full)
#   --dataset   DIR     dir of <ext_id>.crx packages        (/home/gobbi/experiment/DATASET)
#   --chrome    PATH    chrome binary (CONTAINER path)      (/work/verifier/../chrome-126/...)
#   -h | --help         this help
#
# NOTES:
#   * Your home is mounted at /work, so ~/verifier -> /work/verifier inside the container.
#   * Run one experiment at a time: the wait loop matches this run's containers by name
#     (vext_<out>_*), so distinct --out names may overlap, but reusing an --out will not.
#   * Never `docker stop/rm/prune` without a name filter on a shared box.

set -euo pipefail

# ---- defaults -------------------------------------------------------------
IMAGE="verify-ext-${USER}"
PREFIX="z"
SHARDS=100
TIMEOUT=600
OUT="verification"
CATEGORY="none"
MAXV="none"
SAMPLE="all"
ARTIFACTS="true"
PAYLOAD_TIMEOUT=""
STORAGE_POLL="false"
EXTRA_VERIFY=""
WEBSTORE_PAGE="false"
SPOOF="false"
VERIFY_DL="false"
SRC="${HOME}/verifier/analysis/full"
DATASET="/home/gobbi/experiment/DATASET"
CHROME="/work/chrome-126/chrome-linux64/chrome"

# host + container roots (home mounted at /work)
ANA_HOST="${HOME}/verifier/analysis"
CODE_HOST="${HOME}/verifier/extension_code"
VROOT="/work/verifier"

usage() { sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

CMD="${1:-}"; shift || true
[ -z "$CMD" ] && usage 1
case "$CMD" in -h|--help|help) usage 0;; esac

# score takes positional dirs; parse them before the flag loop
SCORE_DIRS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2;;
    --prefix) PREFIX="$2"; shift 2;;
    --shards) SHARDS="$2"; shift 2;;
    --timeout) TIMEOUT="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --category) CATEGORY="$2"; shift 2;;
    --max-vulns) MAXV="$2"; shift 2;;
    --sample) SAMPLE="$2"; shift 2;;
    --artifacts) ARTIFACTS="$2"; shift 2;;
    --payload-timeout) PAYLOAD_TIMEOUT="$2"; shift 2;;
    --storage-poll) STORAGE_POLL="$2"; shift 2;;
    --extra-verify-apis) EXTRA_VERIFY="$2"; shift 2;;
    --web-storage-page-origin) WEBSTORE_PAGE="$2"; shift 2;;
    --spoof) SPOOF="$2"; shift 2;;
    --verify-downloads) VERIFY_DL="$2"; shift 2;;
    --src) SRC="$2"; shift 2;;
    --dataset) DATASET="$2"; shift 2;;
    --chrome) CHROME="$2"; shift 2;;
    -h|--help) usage 0;;
    -*) echo "unknown option: $1" >&2; usage 1;;
    *) SCORE_DIRS+=("$1"); shift;;
  esac
done

# ---- shard ----------------------------------------------------------------
do_shard() {
  echo ">> shard: src=$SRC dataset=$DATASET prefix=$PREFIX shards=$SHARDS category=$CATEGORY sample=$SAMPLE"
  python3 - "$SRC" "$DATASET" "$ANA_HOST" "$CODE_HOST" "$PREFIX" "$SHARDS" "$CATEGORY" "$SAMPLE" <<'PY'
import json, glob, random, shutil, sys
from pathlib import Path
SRC, DATASET, ANA, CODE = map(Path, sys.argv[1:5])
PREFIX, SHARDS, CATEGORY, SAMPLE = sys.argv[5], int(sys.argv[6]), sys.argv[7], sys.argv[8]
cats = None if CATEGORY.lower() in ("none", "", "all") else {c.strip() for c in CATEGORY.split(",") if c.strip()}
sel = []
for f in sorted(glob.glob(str(SRC / "*_result.json"))):
    try:
        s = open(f, encoding="utf-8").read().strip()
        if not s:
            continue
        if s.startswith("```"):
            s = s[s.find("\n") + 1:s.rfind("```")]
        d = json.loads(s)
    except Exception:
        continue
    if any(v.get("result") == "TP" and v.get("attacker_source") in ("Website", "Extension")
           and (cats is None or v.get("vulnerability_category") in cats)
           for v in d.get("vulnerabilities", [])):
        ext = d.get("extension_id") or Path(f).name.replace("_result.json", "")
        if (DATASET / f"{ext}.crx").exists():
            sel.append((ext, f))
print(f"   eligible: {len(sel)}")
if SAMPLE.lower() != "all":
    sel = random.Random(42).sample(sel, min(int(SAMPLE), len(sel)))
CODE.mkdir(parents=True, exist_ok=True)
ANA.mkdir(parents=True, exist_ok=True)
for d in ANA.glob(f"{PREFIX}_*"):
    if d.is_dir():
        for x in d.glob("*.json"):
            x.unlink()
        try:
            d.rmdir()
        except OSError:
            pass
for i in range(SHARDS):
    (ANA / f"{PREFIX}_{i:03d}").mkdir(parents=True, exist_ok=True)
for n, (ext, f) in enumerate(sel):
    shutil.copy2(f, ANA / f"{PREFIX}_{n % SHARDS:03d}" / Path(f).name)
    dst = CODE / f"{ext}.crx"
    if not dst.exists():
        shutil.copy2(DATASET / f"{ext}.crx", dst)
print(f"   sharded {len(sel)} extensions into {SHARDS} shards under {ANA}")
PY
}

# ---- run ------------------------------------------------------------------
write_env() {
  local envfile="$1"
  mkdir -p "$(dirname "$envfile")"
  cat > "$envfile" <<EOF
EXTENSION_CODE_DIR=${VROOT}/extension_code
RESULTS_ANALYSIS_DIR=${VROOT}/analysis
RESULTS_VERIFICATION_DIR=${VROOT}/${OUT}
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
  if [ -n "$PAYLOAD_TIMEOUT" ]; then echo "PAYLOAD_EXECUTION_TIMEOUT=${PAYLOAD_TIMEOUT}" >> "$envfile"; fi
  if [ "$STORAGE_POLL" = "true" ]; then echo "STORAGE_POLL=true" >> "$envfile"; fi
  if [ -n "$VERIFY_DL" ] && [ "$VERIFY_DL" != "false" ]; then echo "VERIFY_DOWNLOADS=${VERIFY_DL}" >> "$envfile"; fi
  if [ -n "$EXTRA_VERIFY" ]; then echo "EXTRA_VERIFY_APIS=${EXTRA_VERIFY}" >> "$envfile"; fi
  if [ "$WEBSTORE_PAGE" = "true" ]; then echo "WEB_STORAGE_PAGE_ORIGIN=true" >> "$envfile"; fi
  return 0
}

do_run() {
  local envfile="${HOME}/verifier/.env.${OUT}"
  write_env "$envfile"

  shopt -s nullglob
  local dirs=("$ANA_HOST"/${PREFIX}_*)
  shopt -u nullglob
  if [ ${#dirs[@]} -eq 0 ]; then
    echo "!! no shards '${PREFIX}_*' under $ANA_HOST — run '$0 shard' first" >&2
    exit 1
  fi

  echo ">> run: image=$IMAGE parallelism=${#dirs[@]} timeout=${TIMEOUT}s out=$OUT category=$CATEGORY max-vulns=$MAXV"
  local start; start=$(date +%s)
  for d in "${dirs[@]}"; do
    local name; name="$(basename "$d")"
    docker run --rm -d --name "vext_${OUT}_${name}" \
      -v "${HOME}:/work" -u "$(id -u):$(id -g)" \
      --env-file "$envfile" -e "RESULTS_TO_VERIFY=${name}" \
      --shm-size=2g "$IMAGE" > /dev/null
  done
  while [ "$(docker ps --filter "name=vext_${OUT}_" -q | wc -l)" -gt 0 ]; do
    echo "$(date +%H:%M:%S) ${OUT} remaining: $(docker ps --filter "name=vext_${OUT}_" -q | wc -l)"
    sleep 20
  done
  echo ">> ${OUT} done - $(( ($(date +%s) - start) / 60 )) min"
}

# ---- score ----------------------------------------------------------------
do_score() {
  if [ ${#SCORE_DIRS[@]} -eq 0 ]; then
    SCORE_DIRS=("$OUT")
  fi
  python3 - "${SCORE_DIRS[@]}" <<'PY'
import json, collections, sys
from pathlib import Path
def load(name):
    base = Path(name)
    if not base.is_absolute():
        base = Path.home() / "verifier" / name
    out = {}
    for f in base.rglob("results/*_result.json"):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        for i, v in enumerate(d.get("vulnerabilities_verified", [])):
            out[(d.get("extension_id"), v.get("rule_id"), i)] = v
    return out
names = sys.argv[1:]
M = {n: load(n) for n in names}
for n in names:
    m = M[n]
    det = sum(1 for v in m.values() if v.get("detection"))
    exts = {k[0] for k in m}
    exts_det = {k[0] for k, v in m.items() if v.get("detection")}
    print(f"\n{n}: findings {det}/{len(m)} = {det/max(len(m),1)*100:.1f}%   "
          f"extensions {len(exts_det)}/{len(exts)}")
    rs = collections.Counter((v.get("failure_reason") or "-") for v in m.values() if not v.get("detection"))
    for r, c in rs.most_common(6):
        print(f"      {c:>6}  {r}")
if len(names) == 2:
    A, B = M[names[0]], M[names[1]]
    common = set(A) & set(B)
    lost = [k for k in common if A[k].get("detection") and not B[k].get("detection")]
    gained = [k for k in common if not A[k].get("detection") and B[k].get("detection")]
    dropped = {k[0] for k in A} - {k[0] for k in B}
    print(f"\ndiff {names[0]} -> {names[1]} (common {len(common)}): "
          f"lost {len(lost)}, gained {len(gained)}, extensions_only_in_{names[0]} {len(dropped)}")
PY
}

# ---- dispatch -------------------------------------------------------------
case "$CMD" in
  shard) do_shard;;
  run)   do_run;;
  score) do_score;;
  all)   do_shard; do_run; do_score;;
  *) echo "unknown command: $CMD" >&2; usage 1;;
esac
