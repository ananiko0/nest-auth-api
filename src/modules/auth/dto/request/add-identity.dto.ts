import { ApiProperty } from '@nestjs/swagger';
import { IsEnum, IsNotEmpty, IsString } from 'class-validator';
import { IdentifierTypeEnum } from '../../types/identifier.enum';

export class AddIdentityDto {
  @ApiProperty({
    description: 'identifier of the user, phone opr email',
    example: 'user@example.com',
  })
  @IsNotEmpty({ message: 'Identifier cannot be empty' })
  @IsString({ message: 'Identifier must be a string' })
  identifier: string;

  @ApiProperty({
    description: 'Type of identifier (email or phone)',
    enum: IdentifierTypeEnum,
    example: IdentifierTypeEnum.EMAIL,
  })
  @IsEnum(IdentifierTypeEnum)
  provider: IdentifierTypeEnum;
}
