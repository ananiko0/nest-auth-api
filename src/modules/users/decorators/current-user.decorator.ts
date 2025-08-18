import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { AuthUser, AuthRequest } from 'src/modules/auth/types/payload.type';

export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext): AuthUser => {
    const request = ctx.switchToHttp().getRequest<AuthRequest>();
    return request.user;
  },
);
