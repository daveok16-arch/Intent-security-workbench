#!/usr/bin/env bash
#
# Download real-world vulnerable applications and benchmark the engines against
# them. This is the honest test of whether detection generalises beyond the
# repository's own fixtures.
#
# Ground truth:
#   - OWASP NodeGoat: documented Insecure Direct Object Reference (A4). Its
#     app/routes/allocations.js even carries a comment describing the fix.
#   - OWASP Juice Shop: documented BOLA challenge (routes/basketItems.ts) plus
#     deliberate hardcoded credentials in routes/login.ts.
#
# The engines are expected to report a SMALL number of findings on these large
# codebases. Hundreds of findings would mean the rules are noise.

set -uo pipefail

CORPUS_DIR="${CORPUS_DIR:-/tmp/corpus}"

mkdir -p "$CORPUS_DIR"
cd "$CORPUS_DIR" || exit 1

clone() {
  local name="$1" url="$2"
  if [[ -d "$name/.git" ]]; then
    echo "  have  $name"
  else
    echo "  clone $name ..."
    git clone -q --depth 1 "$url" "$name" || { echo "  FAILED to clone $name"; return 1; }
  fi
}

echo
echo "Fetching corpus into $CORPUS_DIR"
clone nodegoat  https://github.com/OWASP/NodeGoat.git
clone juiceshop https://github.com/juiceshop/juice-shop.git

echo
echo "=============================================="
echo " Benchmarking"
echo "=============================================="

cd - >/dev/null || exit 1

for target in nodegoat juiceshop; do
  if [[ -d "$CORPUS_DIR/$target" ]]; then
    echo
    echo "--- $target ---"
    npx tsx tools/benchmark_corpus.ts "$CORPUS_DIR/$target" || true
  fi
done

echo
echo "Interpretation:"
echo "  nodegoat  -> 1 finding expected (the documented IDOR in allocations.js)"
echo "  juiceshop -> ~15 findings expected (BOLA in basketItems.ts + hardcoded"
echo "               credentials in login.ts / lib/insecurity.ts)"
echo
echo "Triaging a finding with its surrounding code:"
echo "  npx tsx tools/triage_findings.ts $CORPUS_DIR/nodegoat"
echo