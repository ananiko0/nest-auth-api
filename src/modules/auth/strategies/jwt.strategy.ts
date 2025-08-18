import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../users/users.service';
import { AuthRequest, AuthUser, JwtPayload } from '../types/payload.type';
import { RedisService } from 'src/modules/redis/redis.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    configService: ConfigService,
    private readonly usersService: UsersService,
    private readonly redisService: RedisService,
  ) {
    const jwtSecret = configService.get<string>('JWT_SECRET');
    if (!jwtSecret) {
      throw new Error('JWT_SECRET is not defined in the environment variables');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
      passReqToCallback: true,
    });
  }

  async validate(req: AuthRequest, payload: JwtPayload): Promise<AuthUser> {
    const headerDeviceId = req.headers['x-device-id'] as string | undefined;
    if (!headerDeviceId || payload.deviceId !== headerDeviceId) {
      throw new UnauthorizedException('Device ID mismatch');
    }

    const isBlacklisted = await this.redisService.get(payload.jti);
    if (isBlacklisted === 'blacklisted') {
      throw new UnauthorizedException('Token has been revoked');
    }

    const user = await this.usersService.findOneInternal(payload.sub);
    if (!user || !user.isActive) {
      throw new UnauthorizedException('Invalid or inactive user');
    }

    return {
      id: user.id,
      role: user.role,
      provider: payload.provider,
      identifier: payload.identifier,
      deviceId: payload.deviceId,
    };
  }
}
