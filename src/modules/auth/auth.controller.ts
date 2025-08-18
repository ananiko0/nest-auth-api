import { Controller, Post, Body, UseGuards, Headers } from '@nestjs/common';
import { AuthService } from './auth.service';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import {
  EmailIdentifierCheckDto,
  PhoneIdentifierCheckDto,
} from './dto/request/identifier-check.dto';
import { RegisterWithEmailDto, RegisterWithPhoneDto } from './dto/request/register-user.dto';
import { LoginEmailDto, LoginPhoneDto } from './dto/request/login.dto';
import { VerifyEmailDto, VerifyIdentityDto, VerifyPhoneDto } from './dto/request/verify-otp.dto';
import { DeviceId } from 'src/common/decorators/device-id.decorator';
import { RefreshTokenDto } from './dto/request/refresh-token.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { AccessToken } from './decorators/access-token.decorator';
import { AddIdentityDto } from './dto/request/add-identity.dto';
import { CurrentUser } from '../users/decorators/current-user.decorator';
import { AuthUser } from './types/payload.type';

//some post requests return 201 status code even though we do not actually post anything (check identifier and also login)

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiOperation({ summary: 'Check if email identifier is available' })
  @ApiResponse({ status: 200, description: 'Identifier is available' })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 409, description: 'Identifier already exists' })
  @Post('check-identifier/email')
  async checkEmailIdentifier(@Body() dto: EmailIdentifierCheckDto) {
    return await this.authService.checkIdentifier(dto.identifier);
  }

  @ApiOperation({ summary: 'Check if phone identifier is available' })
  @ApiResponse({ status: 200, description: 'Identifier is available' })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 409, description: 'Identifier already exists' })
  @Post('check-identifier/phone')
  async checkPhoneIdentifier(@Body() dto: PhoneIdentifierCheckDto) {
    return await this.authService.checkIdentifier(dto.identifier);
  }

  @ApiOperation({ summary: 'Regsiter a client with email and password' })
  @ApiResponse({ status: 201, description: 'User registered succesfully and tokens issued' })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 409, description: 'Email, alread in user' })
  @Post('register/email')
  async registerWithEmail(@Body() dto: RegisterWithEmailDto, @DeviceId() deviceId: string) {
    return this.authService.registerWithEmail(dto, deviceId);
  }

  @ApiOperation({ summary: 'Login with email and password' })
  @ApiResponse({ status: 200, description: 'User logged in succesfully and tokens issued' })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 401, description: 'Invalid email or password' })
  @Post('login/email')
  async loginWithEmail(@Body() dto: LoginEmailDto, @DeviceId() deviceId: string) {
    return this.authService.loginWithEmail(dto, deviceId);
  }

  @ApiOperation({ summary: 'Verify phone or email with otp' })
  @ApiResponse({ status: 200, description: 'OTP successfully generated and sent (logged for now)' })
  @ApiResponse({ status: 400, description: 'Invalid input data or idenity not found' })
  @Post('email/verify')
  async verifyEmail(@Body() dto: VerifyEmailDto) {
    return await this.authService.verifyEmail(dto);
  }

  @ApiOperation({ summary: 'Register with phone number' })
  @ApiResponse({ status: 201, description: 'User and Identity is created successfully' })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 409, description: 'Phone already in user' })
  @Post('register/phone')
  async registerWithPhone(@Body() dto: RegisterWithPhoneDto) {
    return this.authService.registerWithPhone(dto);
  }

  @ApiOperation({ summary: 'Verify phone with otp during registration' })
  @ApiResponse({ status: 200, description: 'OTP successfully generated, sent and tokens issued' })
  @ApiResponse({ status: 400, description: 'Invalid input data or identity not found' })
  @Post('register/phone/verify')
  async verifyPhoneRegistration(@Body() dto: VerifyPhoneDto, @DeviceId() deviceId: string) {
    return await this.authService.verifyPhoneRegistration(dto, deviceId);
  }

  @ApiOperation({ summary: 'Log in with phone number' })
  @ApiResponse({ status: 200, description: 'token sent to phone number' })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 401, description: 'Invalid phone' })
  @Post('login/phone')
  async loginWithPhone(@Body() dto: LoginPhoneDto) {
    return this.authService.loginWithPhone(dto);
  }

  @ApiOperation({ summary: 'Verify phone with otp during login' })
  @ApiResponse({ status: 200, description: 'OTP successfully generated, sent and tokens issued' })
  @ApiResponse({ status: 400, description: 'Invalid input data or identity not found' })
  @Post('login/phone/verify')
  async verifyPhoneLogin(@Body() dto: VerifyPhoneDto, @DeviceId() deviceId: string) {
    return await this.authService.verifyPhoneLogin(dto, deviceId);
  }

  //403 is not actually called, later i will probably add token reuse attempt tracking
  @ApiOperation({ summary: 'Renew access token with refresh token' })
  @ApiResponse({ status: 201, description: 'New tokens issued successfully' })
  @ApiResponse({ status: 400, description: 'Invalid request body or refresh token format' })
  @ApiResponse({
    status: 401,
    description: 'Refresh token is invalid, expired, or does not match the user/device',
  })
  @ApiResponse({
    status: 403,
    description: 'Access denied – possible token reuse or tampering detected',
  })
  @ApiResponse({ status: 404, description: 'Associated user or refresh token not found' })
  @ApiResponse({ status: 500, description: 'Unexpected server error' })
  @Post('refresh')
  async refreshTokens(@Body() dto: RefreshTokenDto, @DeviceId() deviceId: string) {
    return await this.authService.refreshTokens(dto, deviceId);
  }

  @ApiOperation({ summary: 'Logout user and revoke tokens' })
  @ApiResponse({ status: 200, description: 'User successfully logged out' })
  @ApiResponse({ status: 401, description: 'Unauthorized or invalid token' })
  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(@DeviceId() deviceId: string, @AccessToken() accessToken: string) {
    return await this.authService.logout(deviceId, accessToken);
  }

  @ApiOperation({ summary: 'Add identity for user' })
  @ApiResponse({ status: 201, description: 'Identity succesfully added, otp sent' })
  @ApiResponse({ status: 409, description: 'Identity already exists' })
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('add-identity')
  async addIdentity(@Body() dto: AddIdentityDto, @CurrentUser() currentUser: AuthUser) {
    return await this.authService.addIdentityForExistingUser(dto, currentUser);
  }

  @ApiOperation({ summary: 'Verift added identity' })
  @ApiResponse({ status: 200, description: 'OTP verified successfully' })
  @ApiResponse({ status: 400, description: 'Identity already verified or bad OTP' })
  @ApiResponse({ status: 403, description: 'User does not own this identity' })
  @ApiResponse({ status: 404, description: 'Identity not found' })
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('verify-identity')
  async verifyIdentity(@Body() dto: VerifyIdentityDto, @CurrentUser() currentUser: AuthUser) {
    return await this.authService.verifyIdentityForExistingUser(dto, currentUser);
  }
}
