-- AlterTable
ALTER TABLE "User"
  ADD COLUMN "totpLoginEnabled" BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN "recoveryCodeLoginEnabled" BOOLEAN NOT NULL DEFAULT true;
