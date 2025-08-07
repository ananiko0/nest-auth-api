import { ApiProperty } from '@nestjs/swagger';
import { Exclude, Expose } from 'class-transformer';
import { User } from 'src/modules/users/entities/user.entity';
import { UserRole } from 'src/modules/users/types/user-role.enum';

@Exclude()
export class AuthResponseUserDto {
  @ApiProperty({
    description: 'The unique identifier of the user',
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
    description: 'The phone number of the user',
    example: '995599181716',
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

  constructor(user: Pick<User, 'id' | 'email' | 'phone' | 'role'>) {
    this.id = user.id;
    this.email = user.email;
    this.phone = user.phone;
    this.role = user.role;
  }
}

export class AuthResponseDto {
  @ApiProperty({ description: 'Access Token' })
  @Expose()
  accessToken: string;

  @ApiProperty({ description: 'Id Token' })
  @Expose()
  idToken: string;

  @ApiProperty({ description: 'Refresh Token' })
  @Expose()
  refreshToken: string;

  @ApiProperty({ type: AuthResponseUserDto })
  @Expose()
  user: AuthResponseUserDto;

  constructor(data: {
    accessToken: string;
    idToken: string;
    refreshToken: string;
    user: AuthResponseUserDto;
  }) {
    this.accessToken = data.accessToken;
    this.idToken = data.idToken;
    this.refreshToken = data.refreshToken;
    this.user = data.user;
  }
}
