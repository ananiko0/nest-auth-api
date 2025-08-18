import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RefreshTokenDto {
  @ApiProperty({
    description: 'The refresh token',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  @IsString()
  @IsNotEmpty()
  incomingRefreshToken: string;

  @ApiProperty({
    description: 'Expired Access token',
    example: 'aosidjasidjaoisjdaisdjisd123...',
  })
  @IsString()
  @IsNotEmpty()
  expiredAccessToken: string;
}
