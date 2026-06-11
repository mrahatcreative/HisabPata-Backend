#!/bin/sh
set -e

# Resolve any previously-failed migration so new ones can apply
echo "Resolving any failed migrations..."
npx prisma migrate resolve --applied 20260609053459_optimize_schema 2>/dev/null || true

echo "Running Prisma migrations..."
npx prisma migrate deploy

echo "Starting application..."
exec "$@"
