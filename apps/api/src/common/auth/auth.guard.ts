// import {
//   CanActivate,
//   ExecutionContext,
//   Injectable,
//   UnauthorizedException,
// } from '@nestjs/common'
// import { GqlExecutionContext } from '@nestjs/graphql'
// import { JwtService } from '@nestjs/jwt'
// import { Reflector } from '@nestjs/core'
// import { Role } from 'src/common/types'
// import { PrismaService } from 'src/common/prisma/prisma.service'

// @Injectable()
// export class AuthGuard implements CanActivate {
//   constructor(
//     private readonly jwtService: JwtService,
//     private readonly reflector: Reflector,
//     private readonly prisma: PrismaService,
//   ) {}
//   async canActivate(context: ExecutionContext): Promise<boolean> {
//     const ctx = GqlExecutionContext.create(context)
//     const req = ctx.getContext().req

//     await this.authenticateUser(req)

//     return this.authorizeUser(req, context)
//   }

//   private async authenticateUser(req: any): Promise<void> {
//     const bearerHeader = req.headers.authorization
//     console.log('Authorization header:', bearerHeader); // Log the authorization header
//     // Bearer eylskfdjlsdf309
//     const token = bearerHeader?.split(' ')[1]

//     if (!token) {
//       throw new UnauthorizedException('No token provided.')
//     }

//     try {
//       const payload = await this.jwtService.verify(token)
//       const uid = payload.uid
//       if (!uid) {
//         throw new UnauthorizedException(
//           'Invalid token. No uid present in the token.',
//         )
//       }

//       const user = await this.prisma.user.findUnique({ where: { uid } })
//       if (!user) {
//         throw new UnauthorizedException(
//           'Invalid token. No user present with the uid.',
//         )
//       }

//       console.log('jwt payload: ', payload)
//       req.user = payload
//     } catch (err) {
//       console.error('Token validation error:', err)
//       //throw err
//       throw new UnauthorizedException('Invalid token.'); // Provide a generic message
//     }

//     if (!req.user) {
//       throw new UnauthorizedException('Invalid token.')
//     }
//   }

//   private async authorizeUser(
//     req: any,
//     context: ExecutionContext,
//   ): Promise<boolean> {
//     const requiredRoles = this.getMetadata<Role[]>('roles', context)
//     const userRoles = await this.getUserRoles(req.user.uid)
//     req.user.roles = userRoles

//     if (!requiredRoles || requiredRoles.length === 0) {
//       return true
//     }

//     return requiredRoles.some((role) => userRoles.includes(role))
//   }

//   private getMetadata<T>(key: string, context: ExecutionContext): T {
//     return this.reflector.getAllAndOverride<T>(key, [
//       context.getHandler(),
//       context.getClass(),
//     ])
//   }

//   private async getUserRoles(uid: string): Promise<Role[]> {
//     const roles: Role[] = []

//     const [admin, manager, valet] = await Promise.all([
//       this.prisma.admin.findUnique({ where: { uid } }),
//       this.prisma.manager.findUnique({ where: { uid } }),
//       this.prisma.valet.findUnique({ where: { uid } }),
//       // Add promises for other role models here
//     ])

//     admin && roles.push('admin')
//     manager && roles.push('manager')
//     valet && roles.push('valet')

//     return roles
//   }
// }
//----------------------------------------------------------------------------------------------------
import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { Reflector } from '@nestjs/core';
import { Role } from 'src/common/types';
import { PrismaService } from 'src/common/prisma/prisma.service';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const ctx = GqlExecutionContext.create(context);
    const req = ctx.getContext().req;

    await this.authenticateUser(req);

    return this.authorizeUser(req, context);
  }

  private async authenticateUser(req: any): Promise<void> {
    // Hardcoded UIDs for testing
    const valetuid = 'b4c5da68-7969-4575-a08e-b72dd7dc28a1';
    const adminUid = '5b87b014-23f9-49f9-b1b3-c1dc71d01d4a'; // admin1
    const managerUid = 'a3f5533d-7ff4-4019-8c6f-31ff73e9913b'; // manager1

    // For testing, decide which user to authenticate (Admin or Manager)
    // Defaulting to Manager UID for now
    const hardcodedUid = managerUid;

    // Fetch the user based on the hardcoded UID
    const user = await this.prisma.user.findUnique({
      where: { uid: hardcodedUid },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid uid. User not found.');
    }

    // Attach the user details and UID to the request
    req.user = { uid: hardcodedUid };
  }

  private async authorizeUser(
    req: any,
    context: ExecutionContext,
  ): Promise<boolean> {
    const requiredRoles = this.getMetadata<Role[]>('roles', context);
    const userRoles = await this.getUserRoles(req.user.uid);

    req.user.roles = userRoles;

    if (!requiredRoles || requiredRoles.length === 0) {
      return true; // No roles required, grant access
    }

    const hasAccess = true;

    if (!hasAccess) {
      throw new UnauthorizedException('User does not have the required roles.');
    }

    return hasAccess;
  }

  private getMetadata<T>(key: string, context: ExecutionContext): T {
    return this.reflector.getAllAndOverride<T>(key, [
      context.getHandler(),
      context.getClass(),
    ]);
  }

  private async getUserRoles(uid: string): Promise<Role[]> {
    const roles: Role[] = [];

    // Check if the user belongs to various roles using their UID
    const [admin, manager, valet] = await Promise.all([
      this.prisma.admin.findUnique({ where: { uid } }),
      this.prisma.manager.findUnique({ where: { uid } }),
      this.prisma.valet.findUnique({ where: { uid } }),
    ]);

    if (admin) roles.push('admin'); // Check Admin role
    if (manager) roles.push('manager'); // Check Manager role
    if (valet) roles.push('valet'); // Check Valet role

    return roles;
  }
}