#!/usr/bin/env bash
set -e
set -o pipefail

total=0
passed=0
ord=${1:-''}

readonly log='testsuite.log'
readonly extent='testsuite.ext'

function run() {
  total=$((total + 1))
  echo -n "${total}. $1 ... "
  if [ -n "$ord" ] && [ "$total" -ne "$ord" ]; then
    echo "skipped"
    return
  fi
  if ! valgrind --tool=memcheck --leak-check=full --track-origins=yes --error-exitcode=1 ./drvperf $1 "$extent" &>"$log"; then
    echo "failed"
  else
    echo "passed"
    passed=$((passed + 1))
  fi
}

if ! [ -f "$extent" ]; then
  fallocate -l $((1000*1000*1000)) "$extent"
fi

run "seqread --probes 20 --probe-length $((1024*1024))"
run "seqwrite --probes 20 --probe-length $((1024*1024))"
run "rndread --probes 500 --concurrent 2"
run "rndwrite --probes 500"
run "fullstroke"
run "tracktotrack --cache keep --maxcylsize $((1024*1024))"
run "cncread --probes 250"
run "cncwrite --probes 50"

echo "Tests passed: $passed/$total"

