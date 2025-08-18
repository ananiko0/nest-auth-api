import { IsEmail, IsString, MinLength, IsOptional, IsArray } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Exclude } from 'class-transformer';
import { UserRole } from 'src/modules/users/types/user-role.enum';

export class RegisterLawyerDto {
  @ApiProperty({
    description: 'The email address of the lawyer',
    example: 'lawyer@example.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'The password of the lawyer',
    example: 'password123',
    minLength: 8,
  })
  @IsString()
  @MinLength(8)
  password: string;

  @ApiProperty({
    description: 'The first name of the lawyer',
    example: 'Jane',
  })
  @IsString()
  firstName: string;

  @ApiProperty({
    description: 'The last name of the lawyer',
    example: 'Smith',
  })
  @IsString()
  lastName: string;

  @ApiProperty({
    description: 'The phone number of the lawyer',
    example: '+1234567890',
    required: false,
  })
  @IsString()
  @IsOptional()
  phoneNumber?: string;

  @ApiProperty({
    description: 'The bar number of the lawyer',
    example: 'BAR123456',
  })
  @IsString()
  barNumber: string;

  @ApiProperty({
    description: 'The practice area of the lawyer',
    example: 'Criminal Law',
  })
  @IsString()
  practiceArea: string;

  @ApiProperty({
    description: 'The specializations of the lawyer',
    example: ['Criminal Defense', 'Family Law'],
    type: [String],
  })
  @IsArray()
  @IsString({ each: true })
  specializations: string[];

  @ApiProperty({
    description: 'The bio of the lawyer',
    example: 'Experienced criminal defense attorney with 10 years of practice',
    required: false,
  })
  @IsString()
  @IsOptional()
  bio?: string;

  @ApiProperty({
    description: 'The website of the lawyer',
    example: 'https://www.lawyerwebsite.com',
    required: false,
  })
  @IsString()
  @IsOptional()
  website?: string;

  @Exclude()
  get role(): UserRole {
    return UserRole.LAWYER;
  }
}
