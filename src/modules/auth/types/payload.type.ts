import { UserRole } from 'src/modules/users/types/user-role.enum';
import { IdentifierTypeEnum } from './identifier.enum';

export type JwtPayload = {
  sub: string;
  jti: string;
  provider: IdentifierTypeEnum;
  identifier: string;
  role: UserRole;
  deviceId: string;
  exp?: number;
  iat?: number;
};

export interface AuthRequest extends Request {
  user: AuthUser;
}

export interface AuthUser {
  id: string;
  provider: IdentifierTypeEnum;
  identifier: string;
  role: UserRole;
  deviceId: string;
}
