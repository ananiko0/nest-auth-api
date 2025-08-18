import { Test, TestingModule } from '@nestjs/testing';
import { JwtStrategy } from './jwt.strategy';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../users/users.service';
import { UnauthorizedException } from '@nestjs/common';
import { User, UserRole } from '../../users/entities/user.entity';

describe('JwtStrategy', () => {
  let strategy: JwtStrategy;
  let usersService: UsersService;

  const mockUser: Partial<User> = {
    id: '1',
    email: 'test@example.com',
    firstName: 'Test',
    lastName: 'User',
    role: UserRole.CLIENT,
    isActive: true,
  };

  const mockUsersService = {
    findOne: jest.fn(),
  };

  const mockConfigService = {
    get: jest.fn().mockReturnValue('test-secret'),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JwtStrategy,
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
      ],
    }).compile();

    strategy = module.get<JwtStrategy>(JwtStrategy);
    usersService = module.get<UsersService>(UsersService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('should be defined', () => {
    expect(strategy).toBeDefined();
  });

  describe('validate', () => {
    const payload = {
      sub: '1',
      email: 'test@example.com',
    };

    it('should return user if token is valid and user is active', async () => {
      mockUsersService.findOne.mockResolvedValue(mockUser);

      const result = await strategy.validate(payload);

      expect(result).toBe(mockUser);
      expect(usersService.findOne).toHaveBeenCalledWith(payload.sub);
    });

    it('should throw UnauthorizedException if user is not found', async () => {
      mockUsersService.findOne.mockResolvedValue(null);

      await expect(strategy.validate(payload)).rejects.toThrow(UnauthorizedException);
      expect(usersService.findOne).toHaveBeenCalledWith(payload.sub);
    });

    it('should throw UnauthorizedException if user is not active', async () => {
      const inactiveUser = { ...mockUser, isActive: false };
      mockUsersService.findOne.mockResolvedValue(inactiveUser);

      await expect(strategy.validate(payload)).rejects.toThrow(UnauthorizedException);
      expect(usersService.findOne).toHaveBeenCalledWith(payload.sub);
    });
  });
});
