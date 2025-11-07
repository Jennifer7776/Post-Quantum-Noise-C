#!/usr/bin/env bash

color() { # $1: name  $2..: text
  case "$1" in
    red)    printf "\033[31m%s\033[0m" "${*:2}";;
    green)  printf "\033[32m%s\033[0m" "${*:2}";;
    yellow) printf "\033[33m%s\033[0m" "${*:2}";;
    blue)   printf "\033[34m%s\033[0m" "${*:2}";;
    *)      printf "%s" "${*:2}";;
  esac
}

wait_port() { # $1: PORT, $2: timeout sec
  local port="$1" t="${2:-5}" i=0
  while ! lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; do
    sleep 0.1; i=$((i+1))
    [[ $i -ge $((t*10)) ]] && return 1
  done
  return 0
}

kill_on_port() { # $1: PORT
  local port="$1"
  local pids
  pids=$(lsof -t -iTCP:"$port" -sTCP:LISTEN 2>/dev/null | xargs)
  [[ -n "$pids" ]] && kill $pids 2>/dev/null || true
}

ts() { date +"%Y-%m-%d %H:%M:%S"; }
