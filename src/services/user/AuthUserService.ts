import prismaClient from "../../prisma";
import { sign } from "jsonwebtoken";
import { compare } from "bcryptjs";

interface AuthUserRequest {
    email: string
    password: string
}


class AuthUserService {
    async execute({ email, password }: AuthUserRequest) {
        
        const user = await prismaClient.user.findFirst({
           where: {
            email: email
           }
        })

        if(!user){
            throw new Error("Email ou senha incorreto")
        }

        const passwordMath = await compare(password, user?.password)
        if(!passwordMath){
            throw new Error("Email ou senha incorreto")
        }

        // GERAR UM TOKEN JWT
        const token = sign(
            {
               name: user.name,
               email: user.email, 
            },
            process.env.JWT_SECRET,
            {
                subject: user.id,
                expiresIn: '30d'
            }
        )

        return { 
            id: user?.id,
            name: user?.name,
            email: user?.email,
            token: token
         }
    }
}

export { AuthUserService }