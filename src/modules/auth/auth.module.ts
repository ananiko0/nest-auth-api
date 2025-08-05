import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { RefreshToken } from './entities/refresh-token.entity';
import { User } from '@users/entities/user.entity';
import { PasswordResetToken } from './entities/password-reset-token.entity';
import { Identity } from './entities/identity.entity';
import { Otp } from './entities/otp.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      RefreshToken,
      User,
      PasswordResetToken,
      Identity,
      Otp,
    ]),
  ],
  controllers: [AuthController],
  providers: [AuthService],
})
export class AuthModule {}
