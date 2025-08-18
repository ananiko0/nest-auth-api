import { MigrationInterface, QueryRunner } from "typeorm";

export class Amazingmigration1755521059617 implements MigrationInterface {
    name = 'Amazingmigration1755521059617'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TYPE "public"."verification_records_status_enum" AS ENUM('pending', 'approved', 'rejected')`);
        await queryRunner.query(`CREATE TABLE "verification_records" ("id" uuid NOT NULL DEFAULT uuid_generate_v4(), "created_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "updated_at" TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(), "userId" character varying NOT NULL, "status" "public"."verification_records_status_enum" NOT NULL DEFAULT 'pending', "documents" jsonb, "adminNotes" text, "reviewedBy" character varying, "reviewedAt" TIMESTAMP, "rejectionReason" text, "user_id" uuid, CONSTRAINT "PK_9d228cb8a0cbccc5d182cc9c349" PRIMARY KEY ("id"))`);
        await queryRunner.query(`ALTER TABLE "verification_records" ADD CONSTRAINT "FK_a03623dc18d5f21212a23711363" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE NO ACTION`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "verification_records" DROP CONSTRAINT "FK_a03623dc18d5f21212a23711363"`);
        await queryRunner.query(`DROP TABLE "verification_records"`);
        await queryRunner.query(`DROP TYPE "public"."verification_records_status_enum"`);
    }

}
