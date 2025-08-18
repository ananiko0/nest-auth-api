import { IsEmail } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RequestPasswordResetDto {
  @ApiProperty({
    description: 'The email address of the user requesting password reset',
    example: 'user@example.com',
  })
  @IsEmail()
  email: string;
}
