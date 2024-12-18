import { Module } from '@nestjs/common';
import { ProcessorService } from './processor.service';
import { ProcessorController } from './processor.controller';

@Module({
  controllers: [ProcessorController],
  providers: [ProcessorService],
})
export class ProcessorModule {}
