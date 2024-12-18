import { Controller, Get, Post, Body } from '@nestjs/common';
import { RedisService } from './redis.service';

@Controller()
export class RedisController {
  constructor(private readonly redisService: RedisService) {}

  @Post('/add')
  async addData(
    @Body() body: { key: string; value: string; ttl: number }
  ): Promise<string> {
    const { key, value, ttl } = body;
    console.log(body)
    await this.redisService.setKey(key, value, ttl);
    return `Key "${key}" added to Redis with TTL of ${ttl} seconds.`;
  }

  @Get('/get')
  async getData(@Body('key') key: string): Promise<string | null> {
    return await this.redisService.getKey(key);
  }
}
