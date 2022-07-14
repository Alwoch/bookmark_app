import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "../prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from "@prisma/client/runtime";
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";

@Injectable()
export class AuthService{
 constructor(
  private prisma:PrismaService,
  private jwt:JwtService,
  private config:ConfigService
  ){}
 async signup(dto:AuthDto){
  //generate the password hash
  const hash=await argon.hash(dto.password)
  //save the new user in the db
  try {
   const user=await this.prisma.user.create({
    data:{
     email:dto.email,
     hash,
    }
    // select:{
    //  id:true,
    //  email:true,
    //  createdAt:true
    // }
   })
   
   //we can also strip the hash out of the returned user
     //we need to return the saved user
     return this.signToken(user.id,user.email);
  } catch (error) {
   if(error instanceof PrismaClientKnownRequestError){
    if(error.code === 'P2002'){
     throw new ForbiddenException('credentials taken')
    }
   }
   throw error;
  }
 }

 async login(dto:AuthDto){ 
  //find the user by email
  const user=await this.prisma.user.findUnique({
   where:{
    email:dto.email,
   }
  })
  //if the user doesn't exist we throw an exception
  if (!user) throw new ForbiddenException('incorrect credentials')

  //compare passwords
  const pwMatches=await argon.verify(user.hash,dto.password)
  //if the passwords don't match we throw an exception
  if(!pwMatches) throw new ForbiddenException('incorrect credentials')

  //if everything is okay we send back the user(we dont want to send back the user, we only need the token)
  return this.signToken(user.id,user.email)
 }

 //token
  async signToken(
  userId:number,email:string
  ):Promise<{access_token:string}>{
    const payload={
      sub:userId,
      email
    } 
    const secret=this.config.get('JWT_SECRET')
    const token=await this.jwt.sign(payload,{
      expiresIn:'15m',
      secret:secret
    });
    return{
      access_token:token,
    };
  }
}