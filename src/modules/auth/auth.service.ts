import { ConflictException, Injectable } from '@nestjs/common';
import { Identity } from './entities/identity.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(Identity)
    private identityRepo: Repository<Identity>,
  ) {}

  async checkIdentifier(identifier: string): Promise<{ available: boolean }> {
    const existing = await this.identityRepo.findOne({
      where: { identifier },
    });

    if (existing) {
      throw new ConflictException('Identifier already exists');
    }

    return { available: true };
  }
}
