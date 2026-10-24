#!/usr/bin/env bash
# Run pytest with a hard deadline that does not depend on killing it: pytest runs in the background
# with its output in a file, not the step's pipe, and if it is still alive at the deadline this
# script prints the log and exits anyway, so the step ends and the log can still be uploaded.
# Usage: pytest-bounded.sh LOG DEADLINE_SECONDS PYTEST_ARGS...
set -uo pipefail
log=$1 deadline=$2
shift 2
py=.venv/Scripts/python.exe
[[ -x "$py" ]] || py=.venv/bin/python
"$py" -m pytest "$@" >"$log" 2>&1 </dev/null &
pid=$!
end=$((SECONDS + deadline))
while kill -0 "$pid" 2>/dev/null && ((SECONDS < end)); do
  sleep 5
done
# Very long lines stall the runner's log processing; the uploaded artifact keeps them whole.
echo "(lines longer than 4000 bytes are cut here; see the $log artifact)"
cut -c1-4000 "$log"
if kill -0 "$pid" 2>/dev/null; then
  echo "::error::pytest still running after ${deadline}s; see the last test started in $log"
  kill -9 "$pid" 2>/dev/null
  exit 1  # no wait: a process that cannot be killed must not hold the step open
fi
wait "$pid"
