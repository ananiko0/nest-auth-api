import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { EntityManager, Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { CreateUserDto } from './dto/request/create-user.dto';
import { UpdateUserDto } from './dto/request/update-user.dto';
import {
  ExternalUserResponseDto,
  InternalUserResponseDto,
} from './dto/response/user-response.dto';
import * as bcrypt from 'bcrypt';
import { UserRole } from './types/user-role.enum';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly userRepo: Repository<User>,
  ) {}

  // create user functions
  async createUserWithEmail(
    email: string,
    role: UserRole,
    manager: EntityManager,
  ): Promise<User> {
    const user = this.createBaseUser({ email, role }, manager);
    return await manager.save(user);
  }

  async createUserWithPhone(
    phone: string,
    role: UserRole,
    manager: EntityManager,
  ): Promise<User> {
    const user = this.createBaseUser({ phone, role }, manager);
    return await manager.save(user);
  }

  private createBaseUser(data: Partial<User>, manager: EntityManager): User {
    return manager.create(User, {
      ...data,
      isActive: true,
    });
  }

  async findOneInternal(id: string): Promise<InternalUserResponseDto> {
    const user = await this.userRepo.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    return new InternalUserResponseDto(user);
  }

  async findOneExternal(id: string): Promise<ExternalUserResponseDto> {
    const user = await this.userRepo.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    return new ExternalUserResponseDto(user);
  }

  ////////old functions //////

  async create(
    createUserDto: CreateUserDto,
    returnFullEntity = false,
  ): Promise<InternalUserResponseDto | User> {
    const existingUser = await this.userRepo.findOne({
      where: { email: createUserDto.email },
    });

    if (existingUser) {
      throw new ConflictException('Email already exists');
    }

    const user = this.userRepo.create(createUserDto);
    const savedUser = await this.userRepo.save(user);
    return returnFullEntity
      ? savedUser
      : new InternalUserResponseDto(savedUser);
  }

  async findAll(
    page = 1,
    limit = 10,
  ): Promise<{ users: InternalUserResponseDto[]; total: number }> {
    const [users, total] = await this.userRepo.findAndCount({
      skip: (page - 1) * limit,
      take: limit,
      order: { createdAt: 'DESC' },
    });

    return {
      users: users.map((user) => new InternalUserResponseDto(user)),
      total,
    };
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.userRepo.findOne({ where: { email } });
  }

  async update(
    id: string,
    updateUserDto: UpdateUserDto,
  ): Promise<InternalUserResponseDto> {
    const user = await this.userRepo.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }

    if (updateUserDto.email && updateUserDto.email !== user.email) {
      const existingUser = await this.findByEmail(updateUserDto.email);
      if (existingUser) {
        throw new ConflictException('Email already exists');
      }
    }

    if (updateUserDto.password) {
      updateUserDto.password = await bcrypt.hash(updateUserDto.password, 10);
    }

    Object.assign(user, updateUserDto);
    const savedUser = await this.userRepo.save(user);
    return new InternalUserResponseDto(savedUser);
  }

  async remove(id: string): Promise<void> {
    const user = await this.userRepo.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    await this.userRepo.remove(user);
  }

  async changePassword(
    id: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    const user = await this.userRepo.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }

    console.log(currentPassword, newPassword);
    // const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    // if (!isPasswordValid) {
    //   throw new BadRequestException('Current password is incorrect');
    // }
    // console.log(newPassword);

    // user.password = await bcrypt.hash(newPassword, 10);
    await this.userRepo.save(user);
  }

  async deactivateUser(id: string): Promise<void> {
    const user = await this.userRepo.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }

    user.isActive = false;
    await this.userRepo.save(user);
  }

  async activateUser(id: string): Promise<void> {
    const user = await this.userRepo.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }

    user.isActive = true;
    await this.userRepo.save(user);
  }
}
