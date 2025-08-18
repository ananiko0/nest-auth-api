import { Exclude, Expose } from 'class-transformer';
import { ApiProperty } from '@nestjs/swagger';
import { User } from '../../entities/user.entity';
import { UserRole } from '../../types/user-role.enum';

@Exclude()
export class BaseUserResponseDto {
  @ApiProperty({
    description: 'The unique identifier of the user',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  @Expose()
  id: string;

  @ApiProperty({
    description: 'The email address of the user',
    example: 'user@example.com',
  })
  @Expose()
  email: string | null;

  @ApiProperty({
    description: 'The first name of the user',
    example: 'John',
  })
  @Expose()
  firstName: string | null;

  @ApiProperty({
    description: 'The last name of the user',
    example: 'Doe',
  })
  @Expose()
  lastName: string | null;

  @ApiProperty({
    description: 'The phone number of the user',
    example: '+1234567890',
    required: false,
  })
  @Expose()
  phone: string | null;

  @ApiProperty({
    description: 'The role of the user',
    enum: UserRole,
    example: UserRole.CLIENT,
  })
  @Expose()
  role: UserRole;

  constructor(user: User) {
    this.id = user.id;
    this.email = user.email;
    this.firstName = user.first_name;
    this.lastName = user.last_name;
    this.phone = user.phone;
    this.role = user.role;
  }
}

@Exclude()
export class ExternalUserResponseDto extends BaseUserResponseDto {}

@Exclude()
export class InternalUserResponseDto extends BaseUserResponseDto {
  @ApiProperty({
    description: 'Whether the user is active',
    example: true,
  })
  @Expose()
  isActive: boolean;

  @ApiProperty({
    description: 'The date when the user was created',
    example: '2024-01-01T00:00:00.000Z',
  })
  @Expose()
  createdAt: Date;

  @ApiProperty({
    description: 'The date when the user was last updated',
    example: '2024-01-01T00:00:00.000Z',
  })
  @Expose()
  updatedAt: Date;

  constructor(user: User) {
    super(user);
    this.isActive = user.isActive;
    this.createdAt = user.createdAt;
    this.updatedAt = user.updatedAt;
  }
}
