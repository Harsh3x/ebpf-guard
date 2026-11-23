#!/bin/sh
# Train a baseline on the victim's normal traffic (once), then detect.
set -e
TARGET="${TARGET:-victim}"
TRAIN_WINDOWS="${TRAIN_WINDOWS:-12}"      # x WINDOW seconds of normal behaviour
WINDOW="${WINDOW:-5}"
MODEL="/data/model-${TARGET}-${WINDOW}s.pt"   # one baseline per window length
mkdir -p /data
if [ ! -f "$MODEL" ]; then
  sleep 5   # let traffic settle
echo ">> learning baseline of '$TARGET' for $((TRAIN_WINDOWS*WINDOW))s (keep traffic normal!)"
  python3 -m ebpfguard train --source ebpf --container "$TARGET" \
      --windows "$TRAIN_WINDOWS" --window "$WINDOW" --model "$MODEL"
fi
echo ">> monitoring '$TARGET'"
exec python3 -m ebpfguard detect --source ebpf --container "$TARGET" --window "$WINDOW" --model "$MODEL" -v
