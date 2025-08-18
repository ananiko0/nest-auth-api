import {
  Injectable,
  ConflictException,
  BadRequestException,
  InternalServerErrorException,
  UnauthorizedException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import {
  EntityManager,
  Repository,
  DataSource,
  MoreThan,
  IsNull,
} from 'typeorm';
import { Identity } from './entities/identity.entity';
import { User } from '../users/entities/user.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { JwtService } from '@nestjs/jwt';
import {
  RegisterWithEmailDto,
  RegisterWithPhoneDto,
} from './dto/request/register-user.dto';
import * as bcrypt from 'bcrypt';
import { IdentifierTypeEnum } from './types/identifier.enum';
import { UsersService } from '../users/users.service';
import { UserRole } from '../users/types/user-role.enum';
import { LoginEmailDto, LoginPhoneDto } from './dto/request/login.dto';
import { Otp } from './entities/otp.entity';
import { randomInt } from 'crypto';
import {
  VerifyEmailDto,
  VerifyIdentityDto,
  VerifyPhoneDto,
} from './dto/request/verify-otp.dto';
import { OtpTypeEnum } from './types/otp.enum';
import {
  AuthResponseDto,
  AuthResponseUserDto,
} from './dto/response/auth-reponse.dto';
import { RefreshTokenDto } from './dto/request/refresh-token.dto';
import { AuthUser, JwtPayload } from './types/payload.type';
import { RedisService } from '../redis/redis.service';
import { randomUUID } from 'crypto';
import { AddIdentityDto } from './dto/request/add-identity.dto';

//later i should have try catch blocks to catch unexpected erros
//add logs of successful enter or quit or somethings like that
//get token expirations in config file now they are hardcoded and its not the best practice

//currenty i am doing token generation in transaction which takes a lot cpu i might considered moving it away for bettering performance but in this case i should take care of saving refresh token gracefully
//latet i will add audit or log failed login attempts
//throttle or delay brute force
//case normalization for email and maybe for other inputs
//should we add 2factor auth?

//later i should add redis ot something like that to not let throttling happen, or not letting otps to be requested before 30 seconds

@Injectable()
export class AuthService {
  constructor(
    @InjectDataSource() private readonly dataSource: DataSource,
    @InjectRepository(Identity)
    private identityRepo: Repository<Identity>,

    @InjectRepository(User)
    private userRepo: Repository<User>,

    @InjectRepository(RefreshToken)
    private refreshTokenRepo: Repository<RefreshToken>,

    @InjectRepository(Otp)
    private otpRepo: Repository<Otp>,

    private jwtService: JwtService,
    private userService: UsersService,
    private redisService: RedisService,
  ) {}

  private async generateTokens(
    user: User,
    identity: Identity,
    deviceId: string,
  ): Promise<{
    accessToken: string;
    refreshToken: string;
    idToken: string;
    refreshTokenJti: string;
  }> {
    const jti = randomUUID();
    const payload: JwtPayload = {
      sub: user.id,
      jti,
      identifier: identity.identifier,
      role: user.role,
      deviceId,
      provider: identity.provider,
    };

    const accessToken = await this.jwtService.signAsync(payload, {
      expiresIn: '15m',
    });

    const refreshTokenJti = randomUUID();
    const refreshToken = await this.jwtService.signAsync(
      { sub: user.id, jti: refreshTokenJti },
      {
        expiresIn: '7d',
      },
    );

    const idToken = await this.jwtService.signAsync(payload);

    return { accessToken, refreshToken, idToken, refreshTokenJti };
  }

  private async hashAndSaveRefreshToken(
    userId: string,
    refreshToken: string,
    deviceId: string,
    identityId: string,
    jti: string,
    manager?: EntityManager,
  ): Promise<void> {
    const refreshTokenHash = await bcrypt.hash(refreshToken, 12);

    const refreshTokenRepo = manager
      ? manager.getRepository(RefreshToken)
      : this.refreshTokenRepo;
    await refreshTokenRepo.update(
      { userId, jti, deviceId, identityId, is_revoked: false },
      { is_revoked: true },
    );
    const token = refreshTokenRepo.create({
      user: { id: userId } as User,
      identity: { id: identityId } as Identity,
      jti,
      token_hash: refreshTokenHash,
      expires_at: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
      is_revoked: false,
      deviceId,
    });

    await refreshTokenRepo.save(token);
  }

  private async blackListToken(jti: string, ttlSeconds: number) {
    await this.redisService.set(jti, 'blacklisted', ttlSeconds);
  }

  private async isTokenBlacklisted(jti: string): Promise<boolean> {
    const result = await this.redisService.get(jti);
    return result === 'blacklisted';
  }

  private isJwtPayload(obj: unknown): obj is JwtPayload {
    return (
      typeof obj === 'object' &&
      obj !== null &&
      'jti' in obj &&
      'sub' in obj &&
      'deviceId' in obj &&
      'provider' in obj &&
      'identifier' in obj
    );
  }

  private async generateAndSaveOtp(
    identityId: string,
    identifier: string,
    provider: IdentifierTypeEnum,
    type: OtpTypeEnum,
    manager?: EntityManager,
  ): Promise<string> {
    const otpLength = 6;
    const expiresInMinutes = 5;
    const otpCode = randomInt(
      10 ** (otpLength - 1),
      10 ** otpLength,
    ).toString();

    const otpHash = await bcrypt.hash(otpCode, 12);

    const expiresAt = new Date(Date.now() + expiresInMinutes * 60 * 1000);

    const otpRepo = this.getOtpRepo(manager);

    const otp = otpRepo.create({
      identityId,
      identifier,
      provider,
      type,
      otp_hash: otpHash,
      expires_at: expiresAt,
    });

    await otpRepo.save(otp);

    return otpCode;
  }

  private getOtpRepo(manager?: EntityManager): Repository<Otp> {
    return manager ? manager.getRepository(Otp) : this.otpRepo;
  }

  private async validatePassword(
    password: string,
    passwordHash: string,
  ): Promise<void> {
    const isValid = await bcrypt.compare(password, passwordHash);
    if (!isValid) {
      throw new UnauthorizedException('Invalid email or password');
    }
  }

  private async createIdentity(
    userId: string,
    provider: IdentifierTypeEnum,
    identifier: string,
    manager: EntityManager,
    plainPassword?: string,
  ): Promise<Identity> {
    const password_hash = plainPassword
      ? await bcrypt.hash(plainPassword, 12)
      : null;

    const identity = manager.create(Identity, {
      userId,
      provider,
      identifier,
      password_hash,
    });

    return await manager.save(identity);
  }

  async addIdentityForExistingUser(dto: AddIdentityDto, currentUser: AuthUser) {
    const { identifier, provider } = dto;

    const available = await this.checkIdentifier(identifier);
    if (!available) throw new ConflictException('Identifier is not available');

    const existingVerified = await this.identityRepo.findOne({
      where: {
        provider,
        userId: currentUser.id,
        isVerified: true,
      },
    });

    if (existingVerified) {
      throw new BadRequestException(
        `You already have a verified ${provider} identity`,
      );
    }

    await this.dataSource.transaction(async (manager) => {
      const identity = await this.createIdentity(
        currentUser.id,
        provider,
        identifier,
        manager,
      );
      await this.requestOtpForIdentity(
        identity.id,
        identifier,
        provider,
        OtpTypeEnum.VERIFY_IDENTITY,
        manager,
      );
    });

    return {
      message: 'Identity added. Verification code sent.',
    };
  }

  async verifyIdentityForExistingUser(
    dto: VerifyIdentityDto,
    currentUser: AuthUser,
  ) {
    const { identifier, provider, otpCode } = dto;
    const identity = await this.findIdentity(provider, identifier);
    if (!identity) {
      throw new NotFoundException(
        'No identity found for the provided identifier and provider',
      );
    }

    if (identity.userId !== currentUser.id) {
      throw new ForbiddenException(
        'You are not allowed to verify this identity',
      );
    }

    if (identity.isVerified) {
      throw new BadRequestException('Identity already verified');
    }

    const user = identity.user;

    await this.dataSource.transaction(async (manager) => {
      await this.verifyOtpForIdentity(
        identity.id,
        identifier,
        provider,
        otpCode,
        OtpTypeEnum.VERIFY_IDENTITY,
        manager,
      );
      identity.isVerified = true;
      await manager.getRepository(Identity).save(identity);
      user[provider] = identifier;
      await manager.getRepository(User).save(user);
    });

    return { message: 'OTP verified successfully' };
  }

  private async findIdentity(
    provider: IdentifierTypeEnum,
    identifier: string,
  ): Promise<Identity | null> {
    const identity = await this.identityRepo.findOne({
      where: { provider, identifier },
      relations: ['user'],
    });
    return identity;
  }

  private async requestOtpForIdentity(
    identityId: string,
    identifier: string,
    provider: IdentifierTypeEnum,
    type: OtpTypeEnum,
    manager?: EntityManager,
  ): Promise<string> {
    const otpCode = await this.generateAndSaveOtp(
      identityId,
      identifier,
      provider,
      type,
      manager,
    );

    // here will be logic of sending otp via email or phone
    console.log(`OTP for ${identifier}: ${otpCode}`);

    return otpCode;
  }

  private async verifyOtpForIdentity(
    identityId: string,
    identifier: string,
    provider: IdentifierTypeEnum,
    otpCode: string,
    type: OtpTypeEnum,
    manager?: EntityManager,
  ): Promise<void> {
    const otpRepo = this.getOtpRepo(manager);
    const otp = await otpRepo.findOne({
      where: {
        identityId,
        identifier,
        provider,
        type,
        used_at: IsNull(),
        expires_at: MoreThan(new Date()),
      },
      order: { expires_at: 'DESC' },
    });

    if (!otp) {
      throw new NotFoundException('OTP expired or not found');
    }

    const isValid = await bcrypt.compare(otpCode, otp.otp_hash);

    if (!isValid) {
      throw new BadRequestException('OTP is invalid');
    }

    otp.used_at = new Date();
    await otpRepo.save(otp);
  }

  async checkIdentifier(identifier: string): Promise<{ available: boolean }> {
    const existing = await this.identityRepo.findOne({
      where: { identifier },
    });

    if (existing) {
      throw new ConflictException('Identifier already exists');
    }

    return { available: true };
  }

  async registerWithEmail(
    dto: RegisterWithEmailDto,
    deviceId: string,
  ): Promise<AuthResponseDto> {
    const { email, password, role } = dto;

    if (![UserRole.CLIENT, UserRole.LAWYER].includes(role))
      throw new BadRequestException('invalid role');

    const available = await this.checkIdentifier(email);
    if (!available) throw new ConflictException('Email is already in use');

    const { user, accessToken, refreshToken, idToken } =
      await this.dataSource.transaction(async (manager: EntityManager) => {
        const user = await this.userService.createUserWithEmail(
          email,
          role,
          manager,
        );

        const identity = await this.createIdentity(
          user.id,
          IdentifierTypeEnum.EMAIL,
          email,
          manager,
          password,
        );

        await this.requestOtpForIdentity(
          identity.id,
          email,
          IdentifierTypeEnum.EMAIL,
          OtpTypeEnum.VERIFY_IDENTITY,
          manager,
        );

        const tokens = await this.generateTokens(user, identity, deviceId);
        await this.hashAndSaveRefreshToken(
          user.id,
          tokens.refreshToken,
          deviceId,
          identity.id,
          tokens.refreshTokenJti,
          manager,
        );
        return { user, ...tokens };
      });

    return new AuthResponseDto({
      accessToken,
      idToken,
      refreshToken,
      user: new AuthResponseUserDto(user),
    });
  }

  async verifyEmail(dto: VerifyEmailDto): Promise<{ message: string }> {
    const { email, otpCode } = dto;
    const identity = await this.findIdentity(IdentifierTypeEnum.EMAIL, email);
    if (!identity) {
      throw new NotFoundException(
        'No identity found for the provided identifier and provider',
      );
    }

    if (identity.isVerified) {
      throw new BadRequestException('Identity already verified');
    }

    await this.dataSource.transaction(async (manager) => {
      await this.verifyOtpForIdentity(
        identity.id,
        email,
        IdentifierTypeEnum.EMAIL,
        otpCode,
        OtpTypeEnum.VERIFY_IDENTITY,
        manager,
      );
      identity.isVerified = true;
      await manager.getRepository(Identity).save(identity);
    });

    return { message: 'OTP verified successfully' };
  }

  async loginWithEmail(
    dto: LoginEmailDto,
    deviceId: string,
  ): Promise<AuthResponseDto> {
    const { email, password } = dto;

    const identity = await this.findIdentity(IdentifierTypeEnum.EMAIL, email);
    if (!identity) throw new UnauthorizedException('Invalid email or passowrd');

    if (!identity.password_hash) {
      throw new UnauthorizedException('Invalid email or password');
    }

    await this.validatePassword(password, identity.password_hash);

    const user = identity.user;

    if (!user.isActive) {
      throw new ForbiddenException('User account is disabled');
    }
    //todo email verification, if it is not verified and user is logged out what should happen? will front display verification input and then send identity verify request to back?
    if (!identity.isVerified) {
      throw new ForbiddenException('Email is not verified');
    }

    const { accessToken, refreshToken, idToken } =
      await this.dataSource.transaction(async (manager) => {
        const tokens = await this.generateTokens(user, identity, deviceId);
        await this.hashAndSaveRefreshToken(
          user.id,
          tokens.refreshToken,
          deviceId,
          identity.id,
          tokens.refreshTokenJti,
          manager,
        );

        user.lastLoginAt = new Date();
        await manager.getRepository(User).save(user);
        return { ...tokens };
      });

    return new AuthResponseDto({
      accessToken,
      idToken,
      refreshToken,
      user: new AuthResponseUserDto(user),
    });
  }

  async registerWithPhone(
    dto: RegisterWithPhoneDto,
  ): Promise<{ message: string }> {
    const { phone, role } = dto;

    if (![UserRole.CLIENT, UserRole.LAWYER].includes(role))
      throw new BadRequestException('invalid role');

    const available = await this.checkIdentifier(phone);
    if (!available) throw new ConflictException('phone is already in use');

    await this.dataSource.transaction(async (manager: EntityManager) => {
      const user = await this.userService.createUserWithPhone(
        phone,
        role,
        manager,
      );

      const identity = await this.createIdentity(
        user.id,
        IdentifierTypeEnum.PHONE,
        phone,
        manager,
      );

      await this.requestOtpForIdentity(
        identity.id,
        phone,
        IdentifierTypeEnum.PHONE,
        OtpTypeEnum.VERIFY_IDENTITY,
        manager,
      );
    });

    return { message: 'OTP sent to your phone number' };
  }

  async verifyPhoneRegistration(
    dto: VerifyPhoneDto,
    deviceId: string,
  ): Promise<AuthResponseDto> {
    const { phone, otpCode } = dto;

    const identity = await this.findIdentity(IdentifierTypeEnum.PHONE, phone);
    if (!identity) {
      throw new NotFoundException(
        'No identity found for the provided  phone number',
      );
    }

    if (!identity.user) {
      throw new InternalServerErrorException(
        'Identity is not linked to any user',
      );
    }

    if (identity.isVerified) {
      throw new BadRequestException('Identity already verified');
    }

    const user = identity.user;

    const { accessToken, refreshToken, idToken } =
      await this.dataSource.transaction(async (manager) => {
        await this.verifyOtpForIdentity(
          identity.id,
          phone,
          IdentifierTypeEnum.PHONE,
          otpCode,
          OtpTypeEnum.VERIFY_IDENTITY,
          manager,
        );
        identity.isVerified = true;
        await manager.getRepository(Identity).save(identity);

        const tokens = await this.generateTokens(user, identity, deviceId);
        await this.hashAndSaveRefreshToken(
          user.id,
          tokens.refreshToken,
          deviceId,
          identity.id,
          tokens.refreshTokenJti,
          manager,
        );
        return tokens;
      });

    return new AuthResponseDto({
      accessToken,
      idToken,
      refreshToken,
      user: new AuthResponseUserDto(user),
    });
  }

  async loginWithPhone(dto: LoginPhoneDto): Promise<{ message: string }> {
    const { phone } = dto;

    const identity = await this.findIdentity(IdentifierTypeEnum.PHONE, phone);
    if (!identity) throw new UnauthorizedException('Invalid phone number');

    if (!identity.isVerified)
      throw new ForbiddenException('Account is not verified');

    await this.requestOtpForIdentity(
      identity.id,
      phone,
      IdentifierTypeEnum.PHONE,
      OtpTypeEnum.LOGIN,
    );

    return { message: 'Verification Code is sent to your phone' };
  }

  async verifyPhoneLogin(
    dto: VerifyPhoneDto,
    deviceId: string,
  ): Promise<AuthResponseDto> {
    const { phone, otpCode } = dto;

    const identity = await this.findIdentity(IdentifierTypeEnum.PHONE, phone);
    if (!identity) {
      throw new NotFoundException(
        'No identity found for the provided  phone number',
      );
    }

    if (!identity.user) {
      throw new InternalServerErrorException(
        'Identity is not linked to any user',
      );
    }

    if (!identity.isVerified) {
      throw new BadRequestException('Account is not verified');
    }

    const user = identity.user;

    const { accessToken, refreshToken, idToken } =
      await this.dataSource.transaction(async (manager) => {
        await this.verifyOtpForIdentity(
          identity.id,
          phone,
          IdentifierTypeEnum.PHONE,
          otpCode,
          OtpTypeEnum.LOGIN,
          manager,
        );

        const tokens = await this.generateTokens(user, identity, deviceId);
        await this.hashAndSaveRefreshToken(
          user.id,
          tokens.refreshToken,
          deviceId,
          identity.id,
          tokens.refreshTokenJti,
          manager,
        );

        user.lastLoginAt = new Date();
        await manager.getRepository(User).save(user);

        return tokens;
      });

    return new AuthResponseDto({
      accessToken,
      idToken,
      refreshToken,
      user: new AuthResponseUserDto(user),
    });
  }

  async refreshTokens(
    dto: RefreshTokenDto,
    headerDeviceId: string,
  ): Promise<AuthResponseDto> {
    const { incomingRefreshToken, expiredAccessToken } = dto;

    const decoded: unknown = this.jwtService.decode(expiredAccessToken);

    if (!this.isJwtPayload(decoded)) {
      throw new BadRequestException('Invalid or malformed access token');
    }

    const { sub: userId, jti, deviceId, provider, identifier, exp } = decoded;

    if (await this.isTokenBlacklisted(jti))
      throw new UnauthorizedException('token is blacklisted');

    const EXPIRATION_GRACE_MS = 5000;
    if (exp && Date.now() < exp * 1000 - EXPIRATION_GRACE_MS) {
      throw new BadRequestException('Access token is still valid');
    }

    if (headerDeviceId !== deviceId)
      throw new UnauthorizedException('Device ID mismatch');

    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    const identity = await this.findIdentity(provider, identifier);
    if (!identity) throw new UnauthorizedException('Identity not found');

    const existingToken = await this.refreshTokenRepo.findOne({
      where: {
        userId,
        identityId: identity.id,
        deviceId,
        is_revoked: false,
        usedAt: IsNull(),
        expires_at: MoreThan(new Date()),
      },
    });
    if (!existingToken) {
      throw new UnauthorizedException(
        'Refresh token not found or already used',
      );
    }

    const isSame = await bcrypt.compare(
      incomingRefreshToken,
      existingToken.token_hash,
    );
    if (!isSame)
      throw new UnauthorizedException('Refresh token does not match');

    const { accessToken, refreshToken, idToken } =
      await this.dataSource.transaction(async (manager) => {
        existingToken.is_revoked = true;
        existingToken.usedAt = new Date();
        await manager.save(existingToken);

        const tokens = await this.generateTokens(user, identity, deviceId);
        await this.hashAndSaveRefreshToken(
          user.id,
          tokens.refreshToken,
          deviceId,
          identity.id,
          tokens.refreshTokenJti,
          manager,
        );

        user.lastLoginAt = new Date();
        await manager.getRepository(User).save(user);
        return { ...tokens };
      });

    return new AuthResponseDto({
      accessToken,
      idToken,
      refreshToken,
      user: new AuthResponseUserDto(user),
    });
  }

  async logout(
    headerDeviceId: string,
    accessToken: string,
  ): Promise<{ message: string }> {
    if (!accessToken) {
      throw new BadRequestException('Missing access token');
    }
    const decoded: unknown = this.jwtService.decode(accessToken);

    if (!this.isJwtPayload(decoded)) {
      throw new BadRequestException('Invalid or malformed access token');
    }
    const { sub: userId, jti, deviceId, provider, identifier, exp } = decoded;

    const ttlSeconds = exp ? exp - Math.floor(Date.now() / 1000) : 900;

    if (headerDeviceId !== deviceId)
      throw new UnauthorizedException('Device ID mismatch');

    const user = await this.userRepo.findOne({ where: { id: userId } });
    if (!user) throw new NotFoundException('User not found');

    const identity = await this.findIdentity(provider, identifier);
    if (!identity) throw new UnauthorizedException('Identity not found');

    await this.dataSource.transaction(async (manager) => {
      await manager.getRepository(RefreshToken).update(
        {
          userId,
          identityId: identity.id,
          deviceId,
          is_revoked: false,
          usedAt: IsNull(),
        },
        { is_revoked: true, usedAt: new Date() },
      );
      await this.blackListToken(jti, ttlSeconds);
    });

    return { message: 'user logged out successfully' };
  }
}
