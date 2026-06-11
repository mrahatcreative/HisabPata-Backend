-- AlterTable
ALTER TABLE "Transaction" ALTER COLUMN "updateHistory" SET DEFAULT ARRAY[]::JSONB[];
