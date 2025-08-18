import { Controller, Get, Post, Body, Param, UseGuards } from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { CurrentUser } from './decorators/current-user.decorator';
import { AuthUser } from '../auth/types/payload.type';

@ApiTags('Users')
@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @ApiOperation({ summary: 'Get User Profile by its Auth Token' })
  @ApiResponse({ status: 200, description: 'Return the user' })
  @ApiBearerAuth()
  @Get('me')
  @UseGuards(JwtAuthGuard)
  async getCurrentUser(@CurrentUser() currentUser: AuthUser) {
    return await this.usersService.findOneExternal(currentUser.id);
  }

  // @ApiOperation({ summary: 'Get all users' })
  // @ApiResponse({ status: 200, description: 'Return all users' })
  // @ApiBearerAuth()
  // @ApiQuery({ name: 'page', required: false, type: Number })
  // @ApiQuery({ name: 'limit', required: false, type: Number })
  // @Get()
  // @UseGuards(JwtAuthGuard, RolesGuard)
  // @Roles(UserRole.ADMIN)
  // async findAll(
  //   @Query('page') page = 1,
  //   @Query('limit') limit = 10,
  // ): Promise<{ users: UserResponseDto[]; total: number }> {
  //   return this.usersService.findAll(page, limit);
  // }

  // @ApiOperation({ summary: 'Get a user by ID' })
  // @ApiResponse({ status: 200, description: 'Return the user' })
  // @ApiResponse({ status: 404, description: 'User not found' })
  // @ApiBearerAuth()
  // @Get(':id')
  // @UseGuards(JwtAuthGuard, RolesGuard)
  // @Roles(UserRole.ADMIN)
  // async findOne(@Param('id') id: string): Promise<UserResponseDto> {
  //   return this.usersService.findOne(id);
  // }

  // @ApiOperation({ summary: 'Update a user' })
  // @ApiResponse({ status: 200, description: 'User successfully updated' })
  // @ApiResponse({ status: 400, description: 'Invalid input data' })
  // @ApiResponse({ status: 404, description: 'User not found' })
  // @ApiBearerAuth()
  // @Patch(':id')
  // @UseGuards(JwtAuthGuard, RolesGuard)
  // @Roles(UserRole.ADMIN)
  // async update(
  //   @Param('id') id: string,
  //   @Body() updateUserDto: UpdateUserDto,
  // ): Promise<UserResponseDto> {
  //   return this.usersService.update(id, updateUserDto);
  // }

  // @ApiOperation({ summary: 'Delete a user' })
  // @ApiResponse({ status: 200, description: 'User successfully deleted' })
  // @ApiResponse({ status: 404, description: 'User not found' })
  // @ApiBearerAuth()
  // @Delete(':id')
  // @UseGuards(JwtAuthGuard, RolesGuard)
  // @Roles(UserRole.ADMIN)
  // @HttpCode(HttpStatus.NO_CONTENT)
  // async remove(@Param('id') id: string): Promise<void> {
  //   await this.usersService.remove(id);
  // }

  @ApiOperation({ summary: 'Change user password' })
  @ApiResponse({ status: 200, description: 'Password successfully changed' })
  @ApiResponse({ status: 400, description: 'Invalid current password' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiBearerAuth()
  @Post(':id/change-password')
  @UseGuards(JwtAuthGuard)
  async changePassword(
    @Param('id') id: string,
    @Body('currentPassword') currentPassword: string,
    @Body('newPassword') newPassword: string,
  ): Promise<void> {
    await this.usersService.changePassword(id, currentPassword, newPassword);
  }

  // @ApiOperation({ summary: 'Deactivate a user' })
  // @ApiResponse({ status: 200, description: 'User successfully deactivated' })
  // @ApiResponse({ status: 404, description: 'User not found' })
  // @ApiBearerAuth()
  // @Post(':id/deactivate')
  // @UseGuards(JwtAuthGuard, RolesGuard)
  // @Roles(UserRole.ADMIN)
  // @HttpCode(HttpStatus.NO_CONTENT)
  // async deactivateUser(@Param('id') id: string): Promise<void> {
  //   await this.usersService.deactivateUser(id);
  // }

  // @ApiOperation({ summary: 'Activate a user' })
  // @ApiResponse({ status: 200, description: 'User successfully activated' })
  // @ApiResponse({ status: 404, description: 'User not found' })
  // @ApiBearerAuth()
  // @Post(':id/activate')
  // @UseGuards(JwtAuthGuard, RolesGuard)
  // @Roles(UserRole.ADMIN)
  // @HttpCode(HttpStatus.NO_CONTENT)
  // async activateUser(@Param('id') id: string): Promise<void> {
  //   await this.usersService.activateUser(id);
  // }
}
