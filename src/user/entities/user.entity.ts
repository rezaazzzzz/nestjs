import { IsString, IsNotEmpty, IsOptional, IsEnum, IsBoolean } from 'class-validator';
import { UserRole } from './../user.role.enum';

export class User {
  @IsString()
  @IsNotEmpty()
  username: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsEnum(UserRole)
  @IsOptional()
  role?: UserRole = UserRole.USER;

  @IsString()
  @IsOptional()
  status?: 'pending' | 'active' = 'pending'; 

  @IsBoolean()
  @IsOptional()
  profileCompleted?: boolean = false; 
}
