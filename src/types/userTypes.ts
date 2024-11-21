import { EUserRole } from '../constent/userConstent'

export interface IRegisterRequestBody {
    name: string
    email: string
    phone: string
    password: string
    consent: boolean
}

export interface ILoginRequestBody {
    email: string
    password: string
}

export interface IUser {
    name: string
    email: string
    phone: {
        isoCode: string
        countryCode: string
        internationalNumber: string
    }
    timezone: string
    password: string
    consent: boolean
    role: EUserRole
    accountConfirmation: {
        status: boolean
        token: string
        code: string
        timestamp: Date | null
    }
    passwordReset: {
        token: string
        expiry: number | null
        lastResetAt: Date | null
    }
    refreshToken: {
        token: string | null
    }
    lastLoginAt: Date | null
}
