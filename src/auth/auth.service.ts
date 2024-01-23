import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs'
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(@InjectModel(User.name) private userModel: Model<User>) { }

  async create(createUserDto: CreateUserDto): Promise<User> {
    try {
      const { password, ...userData } = createUserDto;
      // 1. Encriptar contrase;a
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      });
      await newUser.save()
      const { password: _, ...user } = newUser.toJSON()
      return user
      // 2. Guardar el usuario
      // 3. Generar el JWT
    } catch (error) {
      console.log(error.code)
      if (error.code == 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists!`)
      }
      throw new InternalServerErrorException(`Something terrible happen`)
    }
  }

  async login(loginDto: LoginDto) {
    const {email, password} = loginDto
    const user = await this.userModel.findOne({email})
    if(!user) {
      throw new UnauthorizedException('Not valid credential -> email')
    }
    if(!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Not valid credential -> password')

    }
    const { password:_, ...rest } =user.toJSON()
    console.log(user.toJSON())

    return {
      ...rest,
      token: 'ABC-123'
    }
    /**
     * User {_id, name, email, roles}
     * Token => 
     */
  }

  findAll() {
    return `This action returns all authADSFDASFADS`;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }
}
