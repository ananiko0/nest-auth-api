import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsMobilePhone, IsNotEmpty, IsString } from 'class-validator';

export class EmailIdentifierCheckDto {
  @ApiProperty({
    description: 'The email address of the user',
    example: 'user@example.com',
  })
  @IsNotEmpty({ message: 'Identifier cannot be empty' })
  @IsString({ message: 'Identifier must be a string' })
  @IsEmail()
  identifier: string;
}

export class PhoneIdentifierCheckDto {
  @ApiProperty({
    description: 'The phone number of the user',
    example: '99559918273',
  })
  @IsNotEmpty({ message: 'Identifier cannot be empty' })
  @IsString({ message: 'Identifier must be a string' })
  @IsMobilePhone()
  identifier: string;
}
