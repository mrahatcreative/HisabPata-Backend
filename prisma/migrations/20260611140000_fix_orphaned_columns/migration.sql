-- Reconciliation: re-add updatedAt columns that the failed optimize_schema
-- (20260609053459) migration was supposed to create. The entire migration
-- was rolled back when ADD COLUMN "updatedAt" TIMESTAMP(3) NOT NULL failed
-- on non-empty tables (no DEFAULT clause). These columns were originally
-- dropped by sync_schema_drift (20260527120000).
--
-- The existing resolve --applied in docker-entrypoint.sh only marks the
-- migration as applied without running its SQL, so this migration brings
-- the database into the expected state.

ALTER TABLE "Organization"
  ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT NOW();

ALTER TABLE "Book"
  ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT NOW();

ALTER TABLE "Complaint"
  ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT NOW();

ALTER TABLE "Transaction"
  ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT NOW();

ALTER TABLE "User"
  ADD COLUMN IF NOT EXISTS "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT NOW();
