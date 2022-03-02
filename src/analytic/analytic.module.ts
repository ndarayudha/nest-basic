import { Module } from '@nestjs/common';
import { AnalyticController } from './analytic.controller';
import { AnalyticService } from './analytic.service';

@Module({
  controllers: [AnalyticController],
  providers: [AnalyticService]
})
export class AnalyticModule {}
