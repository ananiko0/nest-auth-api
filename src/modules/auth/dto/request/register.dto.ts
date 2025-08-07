import { ApiProperty } from '@nestjs/swagger';
import {
  IsEmail,
  IsString,
  MinLength,
  IsEnum,
  IsMobilePhone,
} from 'class-validator';
import { UserRole } from 'src/modules/users/types/user-role.enum';

//later password should have more requirements

export class RegisterWithEmailDto {
  @ApiProperty({
    description: 'The email address of the user',
    example: 'user@example.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'The password of the user',
    example: '12345678',
  })
  @IsString()
  @MinLength(8)
  password: string;

  @ApiProperty({
    description: 'The user role',
    example: 'lawyer or client',
    enum: UserRole,
  })
  @IsEnum(UserRole, { message: 'role must be either lawyer or client' })
  role: UserRole;
}

export class RegisterWithPhoneDto {
  @ApiProperty({
    description: 'The phone number of the user',
    example: '+995599123456',
  })
  @IsMobilePhone()
  phone: string;

  @ApiProperty({
    description: 'The user role',
    example: 'lawyer or client',
    enum: UserRole,
  })
  @IsEnum(UserRole, { message: 'role must be either lawyer or client' })
  role: UserRole;
}
