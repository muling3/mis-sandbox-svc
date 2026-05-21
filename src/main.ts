import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { banner as authBanner, gatewayIdentity } from '@mis/auth-middleware';
import { banner as acBanner, accessGuard } from '@mis/access-control';

const PREFIX = 'api/sandbox';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Kong already authenticated the caller (jwt plugin). These read the
  // forwarded identity and enforce per-service authorization.
  app.use(gatewayIdentity());

  // Service-to-service path: Document Service POSTs submissions and GETs
  // persisted reports. The accessGuard whitelist below is exact-match;
  // the report path has a dynamic /:submissionId segment, so we let
  // anything under /api/sandbox/submissions through with a prefix bypass.
  app.use((req: any, _res: any, next: () => void) => {
    if (
      req.path === '/api/sandbox/submissions' ||
      req.path.startsWith('/api/sandbox/submissions/')
    ) {
      req.__skipAccessGuard = true;
    }
    next();
  });
  app.use((req: any, res: any, next: () => void) => {
    if (req.__skipAccessGuard) return next();
    return accessGuard({
      permission: 'profile:read',
      // Whitelisted in-service (still token-gated by Kong, except the
      // health/ready paths which are also whitelisted in kong.yml).
      allow: ['/api/sandbox/health', '/api/sandbox/ready', '/api/sandbox/me'],
    })(req, res, next);
  });

  app.setGlobalPrefix(PREFIX);
  const port = Number(process.env.PORT) || 3004;
  await app.listen(port);
  console.log(authBanner());
  console.log(acBanner());
  console.log(`mis-sandbox-service listening on http://localhost:${port}/${PREFIX}`);
}
bootstrap();
