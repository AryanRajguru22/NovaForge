-- AlterTable
ALTER TABLE "Credential" ADD COLUMN     "credentialId" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "Credential_credentialId_key" ON "Credential"("credentialId");
