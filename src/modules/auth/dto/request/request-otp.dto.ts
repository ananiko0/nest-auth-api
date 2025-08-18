import { IsEnum, IsNotEmpty, IsString } from 'class-validator';
import { IdentifierTypeEnum } from '../../types/identifier.enum';
import { ApiProperty } from '@nestjs/swagger';
import { OtpTypeEnum } from '../../types/otp.enum';

export class RequestOtpDto {
  @ApiProperty({
    description: 'Useridentifier (email or phone)',
    example: 'user@example.com',
  })
  @IsString()
  @IsNotEmpty()
  identifier: string;

  @ApiProperty({
    description: 'Type of identifier (email or phone)',
    enum: IdentifierTypeEnum,
    example: IdentifierTypeEnum.EMAIL,
  })
  @IsEnum(IdentifierTypeEnum)
  provider: IdentifierTypeEnum;

  @ApiProperty({
    description:
      'type of otp what it will be used for identity verification, payment or something else',
    enum: OtpTypeEnum,
    example: OtpTypeEnum.VERIFY_IDENTITY,
  })
  @IsEnum(OtpTypeEnum)
  type: OtpTypeEnum;
}
