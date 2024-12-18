import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { ProcessorModule } from './processor/processor.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { RedisModule } from './redis/redis.module';
import { UserModule } from './user/user.module';
import { ConfigModule } from '@nestjs/config';
@Module({
  
  imports: [
    ConfigModule.forRoot({
      isGlobal: true, 
    }),
    
    ProcessorModule,RedisModule, UserModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
