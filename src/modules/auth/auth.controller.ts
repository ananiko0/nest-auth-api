import { Body, Controller, Post } from '@nestjs/common';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { AuthService } from './auth.service';
import {
  EmailIdentifierCheckDto,
  PhoneIdentifierCheckDto,
} from './dto/request/checkidentifier.dot';

@ApiTags('Authentification')
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @ApiOperation({ summary: 'check if email identifier is available' })
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
}
