import os from 'os'
import config from '../config/config'
import { parsePhoneNumberWithError } from 'libphonenumber-js'
import { getTimezonesForCountry } from 'countries-and-timezones'
import bcrypt from 'bcrypt'
import { v4 } from 'uuid'
import { randomInt } from 'crypto'
export default {
    getSystemHealth: () => {
        return {
            cpuUsage: os.loadavg(),
            totalMemory: `${(os.totalmem() / 1024 / 1024 / 1024).toFixed(2)} GB ${(((os.totalmem() - os.freemem()) / os.totalmem()) * 100).toFixed(2)} %`,
            freeMemory: `${(os.freemem() / 1024 / 1024 / 1024).toFixed(2)} GB`,
            usedMemory: `${((os.totalmem() - os.freemem()) / 1024 / 1024 / 1024).toFixed(2)} GB`
        }
    },
    getApplicationHealth: () => {
        return {
            enviornment: config.ENV,
            uptime: `${process.uptime().toFixed(2)} seconds`,
            memoryUsage: {
                heapTotal: `${(process.memoryUsage().heapTotal / 1024 / 1024).toFixed(2)} MB`,
                heapUsed: `${(process.memoryUsage().heapUsed / 1024 / 1024).toFixed(2)} MB`
            }
        }
    },
    parsePhoneNumber: (phoneNumber: string) => {
        try {
            const parsedPhoneNumber = parsePhoneNumberWithError(phoneNumber)
            if (parsedPhoneNumber) {
                return {
                    countryCode: parsedPhoneNumber.countryCallingCode,
                    isoCode: parsedPhoneNumber.country,
                    internationalNumber: parsedPhoneNumber.formatInternational()
                }
            }
            return {
                countryCode: null,
                isoCode: null,
                internationalNumber: null
            }
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
        } catch (error) {
            return {
                countryCode: null,
                isoCode: null,
                internationalNumber: null
            }
        }
    },
    countryTimezone: (isoCode: string) => {
        return getTimezonesForCountry(isoCode)
    },
    hashedPassword: (password: string) => {
        return bcrypt.hash(password, 10)
    },
    generateRandumId: () => v4(),
    generateOtp: (length: number) => {
        const min = Math.pow(10, length - 1)
        const max = Math.pow(10, length) - 1
        return randomInt(min, max).toString()
    }
}
