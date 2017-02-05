#!/usr/bin/env bash
set -e
set -o pipefail

function usage() {
  echo "$0 {start|stop|clear|cat}" >&2
  exit 1
}

if [ $# -ne 1 ]; then
  usage
fi
cmd="$1"

readonly debug='/sys/kernel/debug'
if ! [ -d "$debug" ]; then
  mount -t debugfs none "$debug"
fi

case "$cmd" in
  start)
    #bash -c "echo 1 > $debug/tracing/events/block/block_rq_insert/enable"
    bash -c "echo 1 > $debug/tracing/events/block/block_rq_issue/enable"
    bash -c "echo 1 > $debug/tracing/events/block/block_rq_complete/enable"
  ;;
  stop)
    bash -c "echo 0 > $debug/tracing/events/block/block_rq_insert/enable"
    bash -c "echo 0 > $debug/tracing/events/block/block_rq_issue/enable"
    bash -c "echo 0 > $debug/tracing/events/block/block_rq_complete/enable"
  ;;
  clear)
    bash -c "echo > $debug/tracing/trace"
  ;;
  cat)
    exec cat $debug/tracing/trace
  ;;
  *)
    usage
  ;;
esac

