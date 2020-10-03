import { IsOptional, IsIn, IsNotEmpty } from 'class-validator';
import { TaskStatus } from '../task-status.enum';

export class GetTasksFilterDTO {
  @IsOptional()
  @IsIn(Object.keys(TaskStatus))
  status: TaskStatus;

  @IsOptional()
  @IsNotEmpty()
  search: string;
}
