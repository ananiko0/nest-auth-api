import { ThrottlerModuleOptions } from '@nestjs/throttler';

export const throttleConfig: ThrottlerModuleOptions = {
  throttlers: [
    {
      ttl: 60,
      limit: 10,
    },
  ],
};
