-- Align PostgreSQL schema with prisma/schema.prisma (fixes registration + transaction drift)

-- User: legacy NOT NULL updatedAt is absent from Prisma schema → inserts fail
ALTER TABLE "User" DROP COLUMN IF EXISTS "updatedAt";

-- Organization: policy fields + legacy updatedAt
ALTER TABLE "Organization" DROP COLUMN IF EXISTS "updatedAt";
ALTER TABLE "Organization" ADD COLUMN IF NOT EXISTS "approvalPolicy" TEXT NOT NULL DEFAULT 'GLOBALLY_ON';
ALTER TABLE "Organization" ADD COLUMN IF NOT EXISTS "whitelistedUserIds" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];

-- Book: sub-books + legacy updatedAt
ALTER TABLE "Book" DROP COLUMN IF EXISTS "updatedAt";
ALTER TABLE "Book" ADD COLUMN IF NOT EXISTS "parentBookId" TEXT;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'Book_parentBookId_fkey'
  ) THEN
    ALTER TABLE "Book"
      ADD CONSTRAINT "Book_parentBookId_fkey"
      FOREIGN KEY ("parentBookId") REFERENCES "Book"("id")
      ON DELETE SET NULL ON UPDATE CASCADE;
  END IF;
END $$;

-- Transaction: rename date → dateTime, drop legacy updatedAt, add missing columns
ALTER TABLE "Transaction" DROP COLUMN IF EXISTS "updatedAt";

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'Transaction' AND column_name = 'date'
  ) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'Transaction' AND column_name = 'dateTime'
  ) THEN
    ALTER TABLE "Transaction" RENAME COLUMN "date" TO "dateTime";
  END IF;
END $$;

ALTER TABLE "Transaction" ADD COLUMN IF NOT EXISTS "dateTime" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE "Transaction" ADD COLUMN IF NOT EXISTS "recipientOrgId" TEXT;
ALTER TABLE "Transaction" ADD COLUMN IF NOT EXISTS "status" TEXT;
ALTER TABLE "Transaction" ADD COLUMN IF NOT EXISTS "createdById" TEXT;
ALTER TABLE "Transaction" ADD COLUMN IF NOT EXISTS "sourceSubBookId" TEXT;
ALTER TABLE "Transaction" ADD COLUMN IF NOT EXISTS "counterProposedAmount" DOUBLE PRECISION;
ALTER TABLE "Transaction" ADD COLUMN IF NOT EXISTS "counterProposedBy" TEXT;
ALTER TABLE "Transaction" ADD COLUMN IF NOT EXISTS "chainId" TEXT;
ALTER TABLE "Transaction" ADD COLUMN IF NOT EXISTS "chainType" TEXT;
ALTER TABLE "Transaction" ADD COLUMN IF NOT EXISTS "isLiability" BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE "Transaction" ADD COLUMN IF NOT EXISTS "adjustedAmount" DOUBLE PRECISION;
ALTER TABLE "Transaction" ADD COLUMN IF NOT EXISTS "version" INTEGER NOT NULL DEFAULT 1;
ALTER TABLE "Transaction" ADD COLUMN IF NOT EXISTS "clientRef" TEXT;

ALTER TABLE "Transaction" ALTER COLUMN "reconStatus" SET DEFAULT 'approved';

-- updateHistory: single JSONB → JSONB[] (Prisma Json[])
ALTER TABLE "Transaction" ALTER COLUMN "updateHistory" DROP DEFAULT;
ALTER TABLE "Transaction" ALTER COLUMN "updateHistory" TYPE JSONB[] USING (
  CASE
    WHEN "updateHistory" IS NULL THEN ARRAY[]::JSONB[]
    ELSE ARRAY["updateHistory"]::JSONB[]
  END
);
ALTER TABLE "Transaction" ALTER COLUMN "updateHistory" SET DEFAULT ARRAY[]::JSONB[];
UPDATE "Transaction" SET "updateHistory" = ARRAY[]::JSONB[] WHERE "updateHistory" IS NULL;
ALTER TABLE "Transaction" ALTER COLUMN "updateHistory" SET NOT NULL;
