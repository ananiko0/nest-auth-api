import { Entity, Column, OneToMany } from 'typeorm';
import { BaseEntity } from '../../../common/entities/base.entity';
import { Identity } from 'src/modules/auth/entities/identity.entity';
import { RefreshToken } from 'src/modules/auth/entities/refresh-token.entity';
import { PasswordResetToken } from 'src/modules/auth/entities/password-reset-token.entity';
import { UserRole } from '../types/user-role.enum';

// I dont like naming same are camelCase and some are snake case

@Entity('users')
export class User extends BaseEntity {
  @Column({ type: 'varchar', length: 255, unique: true, nullable: true })
  email: string | null;

  @Column({ type: 'varchar', length: 20, unique: true, nullable: true })
  phone: string | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  first_name: string | null;

  @Column({ type: 'varchar', length: 100, nullable: true })
  last_name: string | null;

  @Column({
    type: 'enum',
    enum: UserRole,
    default: UserRole.CLIENT,
    nullable: false,
  })
  role: UserRole;

  @Column({ type: 'varchar', length: 100, nullable: true })
  refresh_token_hash: string | null;

  @Column({ type: 'boolean', default: true })
  isActive: boolean;

  @Column({ type: 'timestamptz', nullable: true })
  lastLoginAt: Date | null;

  @OneToMany(() => Identity, (identity) => identity.user)
  identities: Identity[];

  @OneToMany(() => RefreshToken, (token) => token.user)
  refreshTokens: RefreshToken[];

  @OneToMany(() => PasswordResetToken, (token) => token.user)
  passwordResetTokens: PasswordResetToken[];
}
