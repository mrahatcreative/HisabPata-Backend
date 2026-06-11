#!/bin/sh
set -e

echo "Fixing missing database columns forcefully..."
npx prisma db push --accept-data-loss

echo "Starting application..."
exec "$@"
