import { Request, Response, NextFunction } from 'express'
import { IDecriptedJwt, IUser } from '../types/userTypes'
import quiker from '../util/quiker'
import config from '../config/config'
import databseService from '../service/databseService'
import httpError from '../util/httpError'
import responceseMessage from '../constent/responceseMessage'
interface IAuthenticatedRequest extends Request {
    authenticatedUser: IUser
}

export default async (request: Request, _res: Response, next: NextFunction) => {
    try {
        const req = request as IAuthenticatedRequest
        const { cookies } = req
        const { accessToken } = cookies as {
            accessToken: string | undefined
        }

        if (accessToken) {
            const { userId } = quiker.verifyToken(accessToken, config.ACCESS_TOKEN.SECRET as string) as IDecriptedJwt

            const user = await databseService.findUserById(userId)
            if (user) {
                req.authenticatedUser = user
                return next()
            }
        }
        httpError(next, new Error(responceseMessage.UNAUTHORIZED), req, 401)
    } catch (error) {
        httpError(next, error, request, 500)
    }
}
