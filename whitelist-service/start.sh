#!/usr/bin/env bash
# One-step setup and start for Mac/Linux. Run: ./start.sh
set -e
cd "$(dirname "$0")"

if ! command -v node >/dev/null 2>&1; then
  echo "Node.js is not installed. Install the LTS version from https://nodejs.org and run this again."
  exit 1
fi

if [ ! -d node_modules ]; then
  echo "Installing dependencies, this takes a minute the first time..."
  npm install
fi

node scripts/setup-env.js

echo "Starting server. Press Ctrl+C to stop."
echo "Dashboard: http://localhost:3000/dashboard/"
( sleep 2; (open http://localhost:3000/dashboard/ || xdg-open http://localhost:3000/dashboard/) >/dev/null 2>&1 ) &
npm start
