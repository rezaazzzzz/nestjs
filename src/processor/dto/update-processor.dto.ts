import { PartialType } from '@nestjs/mapped-types';
import { CreateProcessorDto } from './create-processor.dto';

export class UpdateProcessorDto extends PartialType(CreateProcessorDto) {}
