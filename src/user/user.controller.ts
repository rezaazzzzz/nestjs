import { Controller, Get, Post, Body, UseGuards, Patch, Param } from '@nestjs/common';
import { UserService } from './user.service';
import { RolesGuard } from './gaurd/user.gaurd';  
import { JwtAuthGuard } from '././gaurd/authgaurd';  
import { Roles } from './roles'; 
import { UserRole } from './user.role.enum';

@Controller('user')
export class UserController {
  constructor(private userService: UserService) {}

  @Post('login')
  async loginUser(@Body() user: { username: string; password: string }) {
    return await this.userService.loginUser(user);
  }

  @Post('create')
  async createUser(@Body() user: { username: string; password: string }) {
    return await this.userService.createUser(user);
  }

  @Post('request-password-reset')
  async requestPasswordReset(@Body() { username }: { username: string }) {
    return await this.userService.requestPasswordReset(username);
  }

  @Post('admin/approve-password-reset')
  @Roles(UserRole.ADMIN)
  @UseGuards(JwtAuthGuard, RolesGuard)
  async approvePasswordReset(
    @Body() { requestId, newPassword }: { requestId: string, newPassword: string }
  ) {
    return await this.userService.approvePasswordReset(requestId, newPassword);
  }
  

  @Get('admin/password-reset-requests')
  @UseGuards(JwtAuthGuard, RolesGuard)  
  @Roles(UserRole.ADMIN)  
  async getPasswordResetRequests() {
    return await this.userService.getPasswordResetRequests();
  }

@Patch('admin/complete-user/:id')
async completeUser(
  @Param('id') id: string,
  @Body() additionalData: any,
) {
  console.log('Request Received:', { id, additionalData });
  return await this.userService.completeUserProfile(id, additionalData);
}

}
