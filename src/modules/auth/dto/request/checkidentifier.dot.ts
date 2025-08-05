import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsMobilePhone } from 'class-validator';

export class EmailIdentifierCheckDto {
  @ApiProperty({
    description: 'The email address of the user',
    example: 'user@example.com',
  })
  @IsEmail()
  identifier: string;
}

export class PhoneIdentifierCheckDto {
  @ApiProperty({
    description: 'The phone number of the user',
    example: '99559918273',
  })
  @IsMobilePhone()
  identifier: string;
}
