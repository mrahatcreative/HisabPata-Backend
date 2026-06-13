#!/bin/sh
set -e

echo "Fixing missing database columns forcefully..."
npx prisma db push --accept-data-loss

if [ -n "$ADMIN_EMAIL" ] && [ -n "$ADMIN_PASSWORD" ]; then
  echo "Seeding admin account for $ADMIN_EMAIL..."
  node seed-admin.js "$ADMIN_EMAIL" "$ADMIN_PASSWORD"
fi

echo "Starting application..."
exec "$@"
