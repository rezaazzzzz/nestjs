import { IsString, IsNotEmpty } from 'class-validator';

export class User {
  @IsString()
  @IsNotEmpty()
  username: string;

  @IsString()
  @IsNotEmpty()
  password: string;
}
