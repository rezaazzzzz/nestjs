import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt'; 
import { UserService } from './user.service';
import { UserController } from './user.controller';

@Module({
  imports: [
    JwtModule.register({
      secret: 'your-secret-key',
      signOptions: { expiresIn: '60m' }, 
    }),
  ],
  providers: [UserService],
  controllers: [UserController],
})
export class UserModule {}
