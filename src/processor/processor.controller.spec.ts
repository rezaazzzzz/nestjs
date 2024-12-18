import { Test, TestingModule } from '@nestjs/testing';
import { ProcessorController } from './processor.controller';
import { ProcessorService } from './processor.service';
import { INestApplication } from '@nestjs/common';
import * as request from 'supertest';

describe('ProcessorController', () => {
  let app: INestApplication;

  beforeAll(async () => {
    const moduleFixture: TestingModule = await Test.createTestingModule({
      controllers: [ProcessorController],
      providers: [ProcessorService],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  it('should be 200 status', async () => {
    const response = await request(app.getHttpServer()).get('/processId');
    expect(response.status).toBe(200);
  });

  // it('shoulde be 404 error',async()=>{

  //   const response = await request(app.getHttpAdapter()).get('/process');
  //   expect(response.status).toBe(200);

  // })
  
  afterAll(async () => {
    await app.close();  
  });
});
