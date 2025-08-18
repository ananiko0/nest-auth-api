import { createParamDecorator, ExecutionContext, BadRequestException } from '@nestjs/common';

export const AccessToken = createParamDecorator((data: unknown, ctx: ExecutionContext): string => {
  const request = ctx.switchToHttp().getRequest<{ headers: Record<string, string> }>();
  const authHeader = request.headers?.authorization;

  if (!authHeader || typeof authHeader !== 'string') {
    throw new BadRequestException('Missing Authentification header');
  }

  const [type, token] = authHeader.split(' ');

  if (type !== 'Bearer' || !token) {
    throw new BadRequestException('Invalid Authorization header format');
  }

  return token;
});
