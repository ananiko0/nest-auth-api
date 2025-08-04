import { DataSource } from 'typeorm';
import { ConfigService } from '@nestjs/config';

export async function testDatabaseConnection(
  dataSource: DataSource,
  configService: ConfigService,
): Promise<boolean> {
  try {
    if (!dataSource.isInitialized) {
      await dataSource.initialize();
    }

    // Test the connection
    await dataSource.query('SELECT 1');

    console.log('✅ Database connection successful');
    console.log(`📦 Database: ${configService.get('DB_DATABASE')}`);
    console.log(`🔌 Host: ${configService.get('DB_HOST')}`);
    console.log(`🚪 Port: ${configService.get('DB_PORT')}`);

    return true;
  } catch (error: unknown) {
    if (error instanceof Error) {
      console.error('❌ Database connection failed:', error.message);
    } else {
      console.error('❌ Database connection failed:', error);
    }
    return false;
  }
}
