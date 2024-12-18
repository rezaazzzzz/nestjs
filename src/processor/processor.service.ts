import { Injectable } from '@nestjs/common';
import { execSync } from 'child_process';
import * as bcrypt from "bcrypt";

@Injectable()
export class ProcessorService {
 private readonly  allowedProcessorId = 'BFEBFBFF000906EA';
 private alloewdHash :string ; 


 constructor() {
     this.alloewdHash = bcrypt.hashSync(this.allowedProcessorId, 10); 
 }

  getProcessorId(): string {
    try {
      const processorId = execSync('wmic cpu get ProcessorId').toString().split('\n')[1].trim();
      return processorId;
      
    } catch (err) {
      console.error('Error fetching processor ID', err);
      process.exit(1);
    }
  }

 async checkProcessorId():Promise <boolean> {
    const currentProcessorId = this.getProcessorId();
    console.log(currentProcessorId);
    return bcrypt.compare(currentProcessorId,this.alloewdHash)

  }

  getHashedProcessorId(): string {
    return this.alloewdHash; 
  }

  
  
}
