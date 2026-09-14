-- AlterTable
ALTER TABLE "Session" ADD COLUMN     "currentRefreshTokenId" TEXT,
ADD COLUMN     "previousRefreshTokenId" TEXT,
ADD COLUMN     "rotatedAt" TIMESTAMP(3);
