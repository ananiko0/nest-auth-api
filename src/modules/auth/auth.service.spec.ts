import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { getRepositoryToken } from '@nestjs/typeorm';
import { IdentifierCheckDto } from './dto/request/identifier-check.dto';
import { ConflictException } from '@nestjs/common';
import { Repository } from 'typeorm';
import { Identity } from './entities/identity.entity';

describe('AuthService - checkIdentifier', () => {
  let service: AuthService;
  let identityRepo: jest.Mocked<Repository<Identity>>;

  beforeEach(async () => {
    identityRepo = { findOne: jest.fn() } as unknown as jest.Mocked<
      Repository<Identity>
    >;

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: getRepositoryToken(Identity),
          useValue: identityRepo,
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should return available: true if identifier does not exist', async () => {
    identityRepo.findOne.mockResolvedValue(null);

    const dto: IdentifierCheckDto = {
      type: 'email',
      identifier: 'test@example.com',
    };

    const result = await service.checkIdentifier(dto);
    expect(result).toEqual({ available: true });
  });

  it('should throw ConflicException if identifier already exists', async () => {
    identityRepo.findOne.mockResolvedValue({ id: 'existing-id' } as Identity);

    const dto: IdentifierCheckDto = {
      type: 'phone',
      identifier: '+1234567890',
    };

    await expect(service.checkIdentifier(dto)).rejects.toThrow(
      ConflictException,
    );
  });
});
