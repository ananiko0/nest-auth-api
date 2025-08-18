import { Test, TestingModule } from '@nestjs/testing';
import { JwtAuthGuard } from './jwt-auth.guard';
import { ExecutionContext } from '@nestjs/common';
import { createMock } from '@golevelup/ts-jest';
import { JwtStrategy } from '../strategies/jwt.strategy';
import { ConfigService } from '@nestjs/config';
import { UsersService } from '../../users/users.service';

describe('JwtAuthGuard', () => {
  let guard: JwtAuthGuard;
  let jwtStrategy: JwtStrategy;

  const mockUsersService = {
    findById: jest.fn(),
  };

  const mockConfigService = {
    get: jest.fn().mockReturnValue('test-secret'),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        JwtAuthGuard,
        JwtStrategy,
        {
          provide: UsersService,
          useValue: mockUsersService,
        },
        {
          provide: ConfigService,
          useValue: mockConfigService,
        },
      ],
    }).compile();

    guard = module.get<JwtAuthGuard>(JwtAuthGuard);
    jwtStrategy = module.get<JwtStrategy>(JwtStrategy);
  });

  it('should be defined', () => {
    expect(guard).toBeDefined();
  });

  it('should be an instance of JwtAuthGuard', () => {
    expect(guard).toBeInstanceOf(JwtAuthGuard);
  });

  it('canActivate should call super.canActivate', async () => {
    const mockContext = createMock<ExecutionContext>();
    const mockRequest = {
      headers: {
        authorization: 'Bearer test-token',
      },
    };
    mockContext.switchToHttp().getRequest.mockReturnValue(mockRequest);

    const mockSuperCanActivate = jest
      .spyOn(guard, 'canActivate')
      .mockImplementation(async () => true);

    const result = await guard.canActivate(mockContext);

    expect(mockSuperCanActivate).toHaveBeenCalledWith(mockContext);
    expect(result).toBe(true);
  });
});
