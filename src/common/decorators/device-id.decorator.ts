import {
  BadRequestException,
  createParamDecorator,
  ExecutionContext,
} from '@nestjs/common';
import { isUUID } from 'class-validator';

export const DeviceId = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): string => {
    const request = ctx.switchToHttp().getRequest<Request>();
    const deviceId = request.headers['x-device-id'] as string | undefined;

    if (!deviceId || typeof deviceId !== 'string' || !isUUID(deviceId)) {
      throw new BadRequestException('Missing or invalid device ID header');
    }

    return deviceId;
  },
);
