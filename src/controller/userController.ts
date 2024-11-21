import { NextFunction, Request, Response } from 'express'
import httpResponse from '../util/httpResponse'
import responceseMessage from '../constent/responceseMessage'
import httpError from '../util/httpError'
import { ILoginRequestBody, IRegisterRequestBody, IUser } from '../types/userTypes'
import { validateJoiSchema, validationLoginBody, validationRegisterBody } from '../service/validationService'
import quiker from '../util/quiker'
import databseService from '../service/databseService'
import { EUserRole } from '../constent/userConstent'

import emailService from '../service/emailService'
import loger from '../util/loger'
import config from '../config/config'
import dayjs from 'dayjs'
import utc from 'dayjs/plugin/utc'
import { EApplicationEnvionment } from '../constent/application'
dayjs.extend(utc)

interface IRegisterRequest extends Request {
    body: IRegisterRequestBody
}
interface ILoginRequest extends Request {
    body: ILoginRequestBody
}

interface IConfirmRequest extends Request {
    prams: {
        token: string
    }
    query: {
        code: string
    }
}

interface ISelfIdentificationRequest extends Request {
    authenticatedUser: IUser
}
export default {
    register: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { body } = req as IRegisterRequest

            // Todo
            // * body validation
            const { error, value } = validateJoiSchema<IRegisterRequestBody>(validationRegisterBody, body)
            if (error) {
                return httpError(next, error, req, 422)
            }

            // * phone number parsing and validation
            const { name, phone, email, password, consent } = value
            const { countryCode, isoCode, internationalNumber } = quiker.parsePhoneNumber('+' + phone)

            if (!countryCode || !isoCode || !internationalNumber) {
                return httpError(next, responceseMessage.INCORECT_PHONE_NUMBER, req, 422)
            }

            // * Timezone
            const timezone = isoCode ? quiker.countryTimezone(isoCode) : null
            if (!timezone || !timezone.length) {
                return httpError(next, responceseMessage.INCORECT_PHONE_NUMBER, req, 422)
            }

            // * check if user already exist using
            const user = await databseService.findUserByEmail(email)
            if (user) {
                return httpError(next, responceseMessage.ALREADY_EXIST('User', email), req, 422)
            }
            // * encrypt password
            const encryptedPassword = await quiker.hashedPassword(password)
            const token = quiker.generateRandumId()
            const code = quiker.generateOtp(6)
            // * create user
            const payload: IUser = {
                name,
                email,
                phone: {
                    isoCode,
                    countryCode,
                    internationalNumber
                },
                accountConfirmation: {
                    status: false,
                    token,
                    code,
                    timestamp: null
                },
                passwordReset: {
                    token,
                    expiry: null,
                    lastResetAt: null
                },
                refreshToken: {
                    token: null
                },
                lastLoginAt: null,
                role: EUserRole.USER,
                timezone: timezone[0].name,
                password: encryptedPassword,
                consent
            }
            const newUser = await databseService.registerUser(payload)

            // * send verification email

            const confirmationalURL = `${config.FRONTEND_URL}/confirmation/${token}?code=${code}`
            const to = [email]
            const subject = 'Confirm your account'
            const text = `Hey ${name}, Please confirm your email by clicking on this link: ${confirmationalURL}\n\n`
            // console.log(text)

            emailService.sendEmail(to, subject, text).catch((error) => loger.error('EMAIL_SERVICE', { meta: error }))

            httpResponse(req, res, 201, responceseMessage.SUCCESS, { _id: newUser._id, email: newUser.email, role: newUser.role })
        } catch (error) {
            httpError(next, error, req, 500)
        }
    },
    confirmation: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { params, query } = req as IConfirmRequest
            //Todo
            // * confirm user by token and code
            const user = await databseService.findUserByConfirmationTokenAndCode(params.token, query.code)
            if (!user) {
                return httpError(next, new Error(responceseMessage.INVALID_ACCOUNT_CONFIRMATION_TOKEN_OR_CODE), req, 422)
            }

            //  * account is already confirmed
            if (user.accountConfirmation.status) {
                return httpError(next, new Error(responceseMessage.ACCOUNT_ALREADY_CONFIRMED), req, 422)
            }

            // * confirm user
            user.accountConfirmation.status = true
            user.accountConfirmation.timestamp = dayjs().utc().toDate()
            await user.save()

            // * send confirmation email
            const to = [user.email]
            const subject = 'Account Confirmed'
            const text = `Hey ${user.name}, Your account has been successfully confirmed.\n\n`
            emailService.sendEmail(to, subject, text).catch((error) => loger.error('EMAIL_SERVICE', { meta: error }))
            httpResponse(req, res, 200, responceseMessage.SUCCESS, {
                params
            })
        } catch (error) {
            httpError(next, error, req, 500)
        }
    },
    login: async (req: Request, res: Response, next: NextFunction) => {
        try {
            // TODO
            // * validate and parse body
            const { body } = req as ILoginRequest
            const { error, value } = validateJoiSchema<ILoginRequestBody>(validationLoginBody, body)
            if (error) {
                return httpError(next, error, req, 422)
            }

            const { email, password } = value
            // * finnd user by email
            const user = await databseService.findUserByEmail(email, '+password')
            // * validate password
            if (!user) {
                return httpError(next, new Error(responceseMessage.NOT_FOUND('User')), req, 404)
            }
            const isPasswordMatch = await quiker.comparePassword(password, user.password)
            if (!isPasswordMatch) {
                return httpError(next, new Error(responceseMessage.INVALID_CREDENTIALS), req, 404)
            }
            // * generate token
            const accessToken = quiker.genrateToken(
                { userId: user._id, role: user.role },
                config.ACCESS_TOKEN.SECRET as string,
                config.ACCESS_TOKEN.EXPIRY
            )

            const refreshToken = quiker.genrateToken(
                { userId: user._id, role: user.role },
                config.REFRESH_TOKEN.SECRET as string,
                config.REFRESH_TOKEN.EXPIRY
            )
            // * last login
            user.lastLoginAt = dayjs().utc().toDate()
            await user.save()
            // * tokens save

            user.refreshToken.token = refreshToken
            await user.save()

            // * cookie send
            let DOMAIN = ''
            try {
                const url = new URL(req.url, config.SERVER_URL)
                DOMAIN = url.hostname
            } catch (error) {
                loger.error('COOKIES', { meta: error })
            }
            res.cookie('accessToken', accessToken, {
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                maxAge: 10000 * config.ACCESS_TOKEN.EXPIRY,
                httpOnly: true,
                secure: !(config.ENV === EApplicationEnvionment.PRODUCTION)
            }).cookie('refreshToken', refreshToken, {
                path: '/api/v1',
                domain: DOMAIN,
                sameSite: 'strict',
                maxAge: 10000 * config.REFRESH_TOKEN.EXPIRY,
                httpOnly: true,
                secure: !(config.ENV === EApplicationEnvionment.PRODUCTION)
            })
            httpResponse(req, res, 200, responceseMessage.SUCCESS, {
                accessToken,
                refreshToken
            })
        } catch (error) {
            httpError(next, error, req, 500)
        }
    },
    selfIdentification: async (req: Request, res: Response, next: NextFunction) => {
        try {
            const { authenticatedUser } = req as ISelfIdentificationRequest
            httpResponse(req, res, 200, responceseMessage.SUCCESS, authenticatedUser)
        } catch (error) {
            httpError(next, error, req, 500)
        }
    }
}
