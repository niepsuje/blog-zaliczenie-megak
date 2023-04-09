import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable, from, of } from 'rxjs';
import { User } from 'src/user/models/user.interface';
import bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(private readonly jwtService: JwtService) {}

  generateJWT(user: User): Observable<string> {
    return from(this.jwtService.signAsync({ user }));
  }

  async hashPassword(password: string): Promise<Observable<string>> {
    return from<string>(await bcrypt.hash(password, 12));
  }

  comparePasswords(
    newPassword: string,
    passwordHash: string,
  ): Observable<any | boolean> {
    return of<any | boolean>(bcrypt.compare(newPassword, passwordHash));
  }
}
