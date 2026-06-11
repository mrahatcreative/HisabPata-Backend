-- AlterTable
ALTER TABLE "Organization" ALTER COLUMN "categories" SET DEFAULT ARRAY[]::TEXT[],
ALTER COLUMN "whitelistedUserIds" SET DEFAULT ARRAY[]::TEXT[];
