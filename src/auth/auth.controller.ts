import { User } from '.prisma/client';
import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
  Version,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { GetUser } from './decorator';
import { Public } from './decorator/public.decorator';
import { AuthDto } from './dto';
import { AccessTokenGuard } from './guard/at.guard';
import { RefreshTokenGuard } from './guard/rt.guard';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Version('1')
  @Post('signup')
  signup(@Body() authDto: AuthDto) {
    return this.authService.signUp(authDto);
  }

  @Version('1')
  @HttpCode(HttpStatus.OK)
  @Post('signin')
  signin(@Body() authDto: AuthDto) {
    return this.authService.signIn(authDto);
  }

  // * New Auth API
  @Version('2')
  @Post('signup')
  @Public()
  @HttpCode(HttpStatus.CREATED)
  signUpV2(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.signUpV2(authDto);
  }

  @Version('2')
  @Post('signin')
  @Public()
  @HttpCode(HttpStatus.OK)
  signInV2(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.signInV2(authDto);
  }

  @Version('2')
  @Post('logout')
  @UseGuards(AccessTokenGuard)
  @HttpCode(HttpStatus.OK)
  logoutV2(@GetUser() user: User) {
    return this.authService.logoutV2(user);
  }

  @Version('2')
  @Post('refresh')
  @Public()
  @UseGuards(RefreshTokenGuard)
  @HttpCode(HttpStatus.OK)
  refreshTokenV2(
    @GetUser() user: User,
    @GetUser('refreshToken') refreshToken: string,
  ) {
    return this.authService.refreshTokens(user, refreshToken);
  }
}
