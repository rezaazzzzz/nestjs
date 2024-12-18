import { Controller, Get, HttpException, Res } from '@nestjs/common';
import { ProcessorService } from './processor.service';
import { promises as fs } from 'fs';
import * as path from 'path';

@Controller('/processId')
export class ProcessorController {
  constructor(private readonly processorService: ProcessorService) {}

  async sendFile(@Res() res: any): Promise<void> {
  
    const filePath = 'C:\\Users\\Administrator\\Desktop\\nestttttt\\project\\app.txt';  

    try {

      if(! await this.processorService.checkProcessorId()) {
       throw new HttpException("access denied",404)
      }

      const fileContent = await fs.readFile(filePath, 'utf8');
      res.send(fileContent);  
    } catch (err) {
      console.error('Error reading file:', err.message);
      res.status(500).send('<p>Cannot read the specified file.</p>'); 
    }
  }

  @Get()
  async checkProcessor(@Res() res: any): Promise<string> {
    const isValid = this.processorService.checkProcessorId();
    if (isValid) {
      await this.sendFile(res);  
      return `<p>Server is running on a valid processor. ${this.processorService.getHashedProcessorId()}</p>`;
    }
    return `<p>Access Denied: Invalid Processor ID.</p>`;
  }
}
