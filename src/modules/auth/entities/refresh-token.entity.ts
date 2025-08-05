import { Entity, Column, ManyToOne, JoinColumn } from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { BaseEntity } from '../../../common/entities/base.entity';
import { Identity } from './identity.entity';

@Entity('refresh_tokens')
export class RefreshToken extends BaseEntity {
  @Column({ type: 'uuid', name: 'user_id', nullable: false })
  userId: string;

  @ManyToOne(() => User, (user) => user.refreshTokens, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column({ type: 'uuid', name: 'identity_id', nullable: true })
  identityId: string;

  @ManyToOne(() => Identity, (identity) => identity.refreshTokens, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'identity_id' })
  identity: Identity;

  @Column({ type: 'uuid', nullable: false })
  jti: string;

  @Column({
    name: 'token_hash',
    type: 'varchar',
    length: 255,
    unique: true,
    nullable: false,
  })
  tokenHash: string;

  @Column({ name: 'expires_at', type: 'timestamptz', nullable: false })
  expiresAt: Date;

  @Column({
    name: 'is_revoked',
    type: 'boolean',
    default: false,
    nullable: false,
  })
  isRevoked: boolean;

  @Column({ name: 'device_id', type: 'uuid', nullable: false })
  deviceId: string;

  @Column({ name: 'used_at', type: 'timestamp', nullable: true })
  usedAt: Date | null;

  @Column({ name: 'ip_address', type: 'varchar', length: 255, nullable: true })
  ipAddress: string | null;

  @Column({ name: 'user_agent', type: 'text', nullable: true })
  userAgent: string | null;
}
