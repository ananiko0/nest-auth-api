import { BaseEntity } from '../../../common/entities/base.entity';
import { Column, Entity, JoinColumn, ManyToOne } from 'typeorm';
import { IdentifierTypeEnum } from '../types/identifier.enum';
import { Identity } from './identity.entity';
import { OtpTypeEnum } from '../types/otp.enum';

@Entity('otp')
export class Otp extends BaseEntity {
  @Column({ type: 'uuid', name: 'identity_id', nullable: false })
  identityId: string;

  @ManyToOne(() => Identity, (identity) => identity.otps, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'identity_id' })
  identity: Identity;

  @Column({ type: 'enum', enum: IdentifierTypeEnum, nullable: false })
  provider: IdentifierTypeEnum;

  @Column({ type: 'varchar', length: 255, nullable: false })
  identifier: string;

  @Column({ name: 'otp_hash', type: 'varchar', length: 255, nullable: false })
  otpHash: string;

  @Column({ type: 'enum', enum: OtpTypeEnum, nullable: false })
  type: OtpTypeEnum;

  @Column({
    name: 'used_at',
    type: 'timestamptz',
    nullable: true,
    default: null,
  })
  usedAt: Date;

  @Column({ name: 'expires_at', type: 'timestamptz', nullable: false })
  expiresAt: Date;
}
