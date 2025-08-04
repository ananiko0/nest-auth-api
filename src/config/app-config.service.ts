import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AppConfig {
  constructor(private configService: ConfigService) {}

  get port(): number {
    return this.configService.getOrThrow<number>('PORT', 3000);
  }

  get dbHost(): string {
    return this.configService.getOrThrow<string>('DB_HOST');
  }

  get dbPort(): number {
    return this.configService.getOrThrow<number>('DB_PORT', 5432);
  }

  get dbUser(): string {
    return this.configService.getOrThrow<string>('DB_USER');
  }

  get dbPass(): string {
    return this.configService.getOrThrow<string>('DB_PASS');
  }

  get dbName(): string {
    return this.configService.getOrThrow<string>('DB_NAME');
  }

  get jwtSecret(): string {
    return this.configService.getOrThrow<string>('JWT_SECRET');
  }
}
