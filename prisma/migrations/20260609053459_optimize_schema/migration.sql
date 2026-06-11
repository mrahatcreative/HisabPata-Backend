/*
  Warnings:

  - You are about to drop the column `parentBookId` on the `Book` table. All the data in the column will be lost.
  - You are about to drop the column `sourceSubBookId` on the `Transaction` table. All the data in the column will be lost.
  - Added the required column `updatedAt` to the `Book` table without a default value. This is not possible if the table is not empty.
  - Added the required column `updatedAt` to the `Complaint` table without a default value. This is not possible if the table is not empty.
  - Added the required column `updatedAt` to the `Organization` table without a default value. This is not possible if the table is not empty.
  - Added the required column `updatedAt` to the `Transaction` table without a default value. This is not possible if the table is not empty.
  - Made the column `reconStatus` on table `Transaction` required. This step will fail if there are existing NULL values in that column.
  - Added the required column `updatedAt` to the `User` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "Book" DROP CONSTRAINT "Book_parentBookId_fkey";

-- DropForeignKey
ALTER TABLE "Complaint" DROP CONSTRAINT "Complaint_userId_fkey";

-- DropForeignKey
ALTER TABLE "Transaction" DROP CONSTRAINT "Transaction_bookId_fkey";

-- DropForeignKey
ALTER TABLE "Transaction" DROP CONSTRAINT "Transaction_linkedTransactionId_fkey";

-- DropForeignKey
ALTER TABLE "Transaction" DROP CONSTRAINT "Transaction_recipientUserId_fkey";

-- DropIndex
DROP INDEX "AudioNote_userId_status_idx";

-- DropIndex
DROP INDEX "OrganizationMember_userId_idx";

-- DropIndex
DROP INDEX "Transaction_category_idx";

-- DropIndex
DROP INDEX "User_phoneNumber_key";

-- AlterTable
ALTER TABLE "Book" DROP COLUMN "parentBookId",
ADD COLUMN     "updatedAt" TIMESTAMP(3) NOT NULL;

-- AlterTable
ALTER TABLE "Complaint" ADD COLUMN     "updatedAt" TIMESTAMP(3) NOT NULL,
ALTER COLUMN "imageUrls" DROP DEFAULT,
ALTER COLUMN "videoUrls" DROP DEFAULT;

-- AlterTable
ALTER TABLE "Organization" ADD COLUMN     "updatedAt" TIMESTAMP(3) NOT NULL,
ALTER COLUMN "categories" DROP DEFAULT,
ALTER COLUMN "whitelistedUserIds" DROP DEFAULT;

-- AlterTable
ALTER TABLE "OrganizationMember" ALTER COLUMN "permissions" DROP DEFAULT,
ALTER COLUMN "status" SET DEFAULT 'pending';

-- AlterTable
ALTER TABLE "Transaction" DROP COLUMN "sourceSubBookId",
ADD COLUMN     "updatedAt" TIMESTAMP(3) NOT NULL,
ALTER COLUMN "reconStatus" SET NOT NULL,
ALTER COLUMN "updateHistory" DROP DEFAULT;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "updatedAt" TIMESTAMP(3) NOT NULL,
ALTER COLUMN "tokenVersion" SET DEFAULT 0;

-- CreateIndex
CREATE INDEX "AudioNote_userId_idx" ON "AudioNote"("userId");

-- CreateIndex
CREATE INDEX "AudioNote_status_idx" ON "AudioNote"("status");

-- CreateIndex
CREATE INDEX "Book_organizationId_isActive_idx" ON "Book"("organizationId", "isActive");

-- CreateIndex
CREATE INDEX "Complaint_userId_idx" ON "Complaint"("userId");

-- CreateIndex
CREATE INDEX "Complaint_status_idx" ON "Complaint"("status");

-- CreateIndex
CREATE INDEX "Complaint_assignedTo_idx" ON "Complaint"("assignedTo");

-- CreateIndex
CREATE INDEX "Transaction_linkedTransactionId_idx" ON "Transaction"("linkedTransactionId");

-- CreateIndex
CREATE INDEX "Transaction_chainId_idx" ON "Transaction"("chainId");

-- CreateIndex
CREATE INDEX "Transaction_createdById_idx" ON "Transaction"("createdById");

-- CreateIndex
CREATE INDEX "Transaction_recipientOrgId_idx" ON "Transaction"("recipientOrgId");

-- CreateIndex
CREATE INDEX "Transaction_pendingAction_idx" ON "Transaction"("pendingAction");

-- CreateIndex
CREATE INDEX "Transaction_bookId_dateTime_idx" ON "Transaction"("bookId", "dateTime" DESC);

-- CreateIndex
CREATE INDEX "Transaction_bookId_reconStatus_dateTime_idx" ON "Transaction"("bookId", "reconStatus", "dateTime" DESC);

-- CreateIndex
CREATE INDEX "Transaction_chainId_reconStatus_idx" ON "Transaction"("chainId", "reconStatus");

-- CreateIndex
CREATE INDEX "Transaction_reconStatus_bookId_idx" ON "Transaction"("reconStatus", "bookId");

-- CreateIndex
CREATE INDEX "Transaction_reconStatus_createdById_idx" ON "Transaction"("reconStatus", "createdById");

-- AddForeignKey
ALTER TABLE "Complaint" ADD CONSTRAINT "Complaint_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Transaction" ADD CONSTRAINT "Transaction_bookId_fkey" FOREIGN KEY ("bookId") REFERENCES "Book"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
