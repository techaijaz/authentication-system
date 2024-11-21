import { NextFunction, Request, Response } from 'express'
import httpResponse from '../util/httpResponse'
import responceseMessage from '../constent/responceseMessage'
import httpError from '../util/httpError'
import { IRegisterRequestBody, IUser } from '../types/userTypes'
import { validateJoiSchema, validationRegisterBody } from '../service/validationService'
import quiker from '../util/quiker'
import databseService from '../service/databseService'
import { EUserRole } from '../constent/userConstent'

import emailService from '../service/emailService'
import loger from '../util/loger'
import config from '../config/config'
import dayjs from 'dayjs'
import utc from 'dayjs/plugin/utc'

dayjs.extend(utc)

interface IRegisterRequest extends Request {
    body: IRegisterRequestBody
}

interface IConfirmRequest extends Request {
    prams: {
        token: string
    }
    query: {
        code: string
    }
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
                    token: null,
                    expiry: null
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
    }
}
