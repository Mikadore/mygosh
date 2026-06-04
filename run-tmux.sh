#!/usr/bin/env bash
set -euo pipefail

session="${1:-mygosh}"
root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v tmux >/dev/null 2>&1; then
	echo "tmux is required but was not found in PATH" >&2
	exit 1
fi

if tmux has-session -t "$session" 2>/dev/null; then
	echo "tmux session '$session' already exists" >&2
	echo "Attach with: tmux attach -t '$session'" >&2
	exit 1
fi

server_cmd='printf "\033]0;mygosh server\007"; echo "server: go run ./bin serve"; go run ./bin serve; status=$?; echo; echo "server exited with status $status"; exec "${SHELL:-/bin/sh}"'
client_cmd='printf "\033]0;mygosh client\007"; sleep 0.5; echo "client: go run ./bin connect localhost:42022"; go run ./bin connect localhost:42022; status=$?; echo; echo "client exited with status $status"; exec "${SHELL:-/bin/sh}"'

tmux new-session -d -s "$session" -n mygosh -c "$root" "$server_cmd"
tmux split-window -h -t "$session:0" -c "$root" "$client_cmd"
tmux select-layout -t "$session:0" even-horizontal >/dev/null
tmux select-pane -t "$session:0.0"

if [[ -n "${TMUX:-}" ]]; then
	tmux switch-client -t "$session"
else
	tmux attach -t "$session"
fi
