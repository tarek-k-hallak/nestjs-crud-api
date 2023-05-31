import { Injectable, ForbiddenException } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CreateAuthDto } from './dto/create-auth.dto';
import * as argon from 'argon2';

@Injectable()
export class AuthService {
  constructor(private prismaService: PrismaService) {}

  async findUser(createAuthDto: CreateAuthDto) {
    const user = await this.prismaService.user.findFirst({
      where: {
        email: createAuthDto.email,
      },
    });
    return user;
  }

  async signup(createAuthDto: CreateAuthDto) {
    let user = await this.findUser(createAuthDto);
    if (user) {
      throw new ForbiddenException(`Email taken`);
    }

    const hash = await argon.hash(createAuthDto.password);
    user = await this.prismaService.user.create({
      data: {
        email: createAuthDto.email,
        hash,
      },
    });

    delete user.hash;
    return user;
  }

  async login(createAuthDto: CreateAuthDto) {
    const user = await this.findUser(createAuthDto);

    if (!user) {
      throw new ForbiddenException('User or Password is not incorrect!');
    }

    const isAuth = await argon.verify(user.hash, createAuthDto.password);
    if (!isAuth) {
      throw new ForbiddenException('User or Password is not incorrect!');
    }

    delete user.hash;
    return user;
  }
}
