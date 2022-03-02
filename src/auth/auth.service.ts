import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { User } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Tokens } from './types';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async signUp(authDto: AuthDto) {
    // generate the password hash
    const hash = await argon.hash(authDto.password);
    // save the new user in the db
    try {
      const user = await this.prismaService.user.create({
        data: {
          email: authDto.email,
          hash,
        },
      });

      return this.signToken(user.id, user.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Credentials taken');
        }
      }
      throw error;
    }
  }

  async signIn(authDto: AuthDto) {
    // find the user by email
    const user: User | null = await this.prismaService.user.findUnique({
      where: {
        email: authDto.email,
      },
    });

    // if user does not exist throw exception
    if (!user) throw new ForbiddenException('Email tidak ditemukan');

    // compare password
    const passwordMatches = await argon.verify(user.hash, authDto.password);
    // if password incorrect throw exception
    if (!passwordMatches) throw new ForbiddenException('Password salah');

    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.configService.get('JWT_SECRET');

    const token = await this.jwtService.signAsync(payload, {
      expiresIn: '15m',
      secret: secret,
    });

    return {
      access_token: token,
    };
  }

  // * New Auth Logic
  async signUpV2(authDto: AuthDto): Promise<Tokens> {
    // generate the password hash
    const hash = await argon.hash(authDto.password);
    // save the new user in the db
    try {
      const user = await this.prismaService.user.create({
        data: {
          email: authDto.email,
          hash,
        },
      });
      const token = await this.getTokens(user.id, user.email);
      await this.hashRefreshToken(user.id, token.refresh_token);
      return token;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Email sudah digunakan');
        }
      }
      throw error;
    }
  }

  async signInV2(authDto: AuthDto): Promise<Tokens> {
    const user = await this.prismaService.user.findUnique({
      where: {
        email: authDto.email,
      },
    });

    if (!user) throw new ForbiddenException('Email belum terdaftar');

    const passwordMatches = await argon.verify(user.hash, authDto.password);

    if (!passwordMatches) throw new ForbiddenException('Password Salah');

    const tokens = await this.getTokens(user.id, user.email);
    await this.hashRefreshToken(user.id, tokens.refresh_token);
    return tokens;
  }

  async logoutV2(user: User) {
    try {
      await this.prismaService.user.updateMany({
        where: {
          id: user.id,
          hashRt: {
            not: null,
          },
        },
        data: {
          hashRt: null,
        },
      });

      return { statusCode: 200, message: 'Logout berhasil' };
    } catch (error) {
      return { statusCode: 400, message: 'Logout Gagal' };
    }
  }

  async refreshTokens(user: User, refreshToken: string) {
    const userr = await this.prismaService.user.findUnique({
      where: {
        id: user.id,
        email: user.email,
      },
    });

    if (!userr) throw new ForbiddenException('User belum terdaftar');
    if (!userr.hashRt) throw new ForbiddenException('Refresh token is expired');

    const refreshTokenValid = await argon.verify(userr.hashRt, refreshToken);
    if (!refreshTokenValid)
      throw new ForbiddenException('Refresh token not valid');

    const tokens = await this.getTokens(userr.id, userr.email);
    await this.hashRefreshToken(userr.id, tokens.refresh_token);
    return tokens;
  }

  async getTokens(userId: number, email: string): Promise<Tokens> {
    const payload = {
      sub: userId,
      email,
    };

    const JWT_SECRET = this.configService.get('JWT_SECRET');
    const REFRESH_SECRET = this.configService.get('REFRESH_SECRET');

    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: JWT_SECRET,
        expiresIn: 60 * 15,
      }),
      this.jwtService.signAsync(payload, {
        secret: REFRESH_SECRET,
        expiresIn: 60 * 60 * 24 * 7,
      }),
    ]);

    return {
      access_token: accessToken,
      refresh_token: refreshToken,
    };
  }

  async hashRefreshToken(userId: number, refreshToken: string) {
    const hash = await argon.hash(refreshToken);

    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        hashRt: hash,
      },
    });
  }
}
