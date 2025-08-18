import { BaseEntity } from '../../../common/entities/base.entity';
import { User } from '../../users/entities/user.entity';
import { Column, Entity, Index, JoinColumn, ManyToOne, OneToMany } from 'typeorm';
import { IdentifierTypeEnum } from '../types/identifier.enum';
import { Otp } from './otp.entity';
import { RefreshToken } from './refresh-token.entity';

//something should probably be updated about the way i keep password
// i don't like provider_id name and in some codes i call it identifier

@Entity('identity')
@Index(['user', 'provider'], { unique: true })
export class Identity extends BaseEntity {
  @Column({ type: 'uuid', name: 'user_id', nullable: false })
  userId: string;

  @ManyToOne(() => User, user => user.identities, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column({ type: 'enum', enum: IdentifierTypeEnum, nullable: false })
  provider: IdentifierTypeEnum;

  @Column({ type: 'varchar', length: 255, nullable: false })
  identifier: string;

  @Column({ type: 'varchar', length: 255, nullable: true })
  password_hash: string | null;

  @Column({ type: 'boolean', default: false })
  isVerified: boolean;

  @OneToMany(() => Otp, otp => otp.identity)
  otps: Otp[];

  @OneToMany(() => RefreshToken, refreshToken => refreshToken.identity)
  refreshTokens: RefreshToken[];
}
