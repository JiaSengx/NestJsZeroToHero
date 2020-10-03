import { Controller, Body, Post, ValidationPipe } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthCredentialsDto } from './dto/auth-credentials.dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('/signup')
  signUp(
    @Body(ValidationPipe) authCredentialsDTO: AuthCredentialsDto,
  ): Promise<void> {
    return this.authService.signUp(authCredentialsDTO);
  }

  @Post('/signin')
  signIn(
    @Body(ValidationPipe) authCredentialsDTO: AuthCredentialsDto,
  ): Promise<{ accessToken: string }> {
    return this.authService.signIn(authCredentialsDTO);
  }
}
