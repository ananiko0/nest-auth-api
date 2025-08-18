import { IsEmail, IsMobilePhone, IsString, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

//should add more requirements for password later

export class LoginEmailDto {
  @ApiProperty({
    description: 'The email address of the user',
    example: 'user@example.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'The password of the user',
    example: 'password123',
    minLength: 8,
  })
  @IsString()
  @MinLength(8)
  password: string;
}

export class LoginPhoneDto {
  @ApiProperty({
    description: 'The mobile address of the user',
    example: '995599123456',
  })
  @IsMobilePhone()
  phone: string;
}
