import './polyfills';

import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ConfigService } from '@nestjs/config';
import helmet from 'helmet';
import { DataSource } from 'typeorm';
import { testDatabaseConnection } from './common/utils/test-database-connection.util';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableShutdownHooks();

  //get config Servcie and database connection
  const configService = app.get(ConfigService);
  const dataSource = app.get(DataSource);

  // Test database connection
  await testDatabaseConnection(dataSource, configService);

  app.enableCors();
  app.use(helmet());

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    }),
  );

  //swagger config
  const config = new DocumentBuilder()
    .setTitle('Auth API')
    .setDescription('Authentification API with roles')
    .setVersion('1.0')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  //start the application
  const port = configService.get<number>('PORT', 3000);
  await app.listen(port);

  console.log(`🚀 Application is running on: http://localhost:${port}`);
  console.log(
    `📚 API Documentation available at: http://localhost:${port}/api`,
  );
}
bootstrap().catch((err) => {
  console.error('🔥 Error starting the application', err);
});
