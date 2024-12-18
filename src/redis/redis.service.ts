import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { createClient, RedisClientType } from 'redis';

@Injectable()
export class RedisService implements OnModuleDestroy {
  private client: RedisClientType;

  constructor() {
    this.client = createClient({
      url: 'redis://localhost:6379',
      password: null,   
    });

    this.client.on('error', (err) => {
      console.error('Redis Client Error', err);
    });

    this.connectToRedis();
  }

  private async connectToRedis(): Promise<void> {
    try {
      await this.client.connect();
      console.log('Connected to Redis');
    } catch (error) {
      console.error('Error connecting to Redis:', error);
    }
  }

  async setKey(key: string, value: string, ttl: number): Promise<void> {
    await this.client.set(key, value, {
      EX: ttl, 
    });
  }

  async getKey(key: string): Promise<string | null> {
    return await this.client.get(key);
  }

  async delKey(key: string): Promise<void> {
    await this.client.del(key);
  }

  async onModuleDestroy() {
    await this.client.quit(); 
}
}


