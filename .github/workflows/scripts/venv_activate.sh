#!/bin/bash

# shellcheck source=/dev/null
if [[ -f venv/bin/activate ]]; then
  source venv/bin/activate
elif [[ -f venv/Scripts/activate ]]; then
  source venv/Scripts/activate
else
  echo "Cannot activate venv sandbox. Failing"
  exit 1
fi

echo "Successfully activated venv sandbox. Python is at `which python`"
