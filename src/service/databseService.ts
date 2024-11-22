import mongoose from 'mongoose'
import config from '../config/config'
import userModel from '../model/userModel'
import { IUser } from '../types/userTypes'

export default {
    connect: async () => {
        try {
            await mongoose.connect(config.DATABASE_URL as string)
            return mongoose.connection
        } catch (error) {
            throw error
        }
    },
    findUserByEmail: (email: string, select: string = '') => {
        return userModel.findOne({ email }).select(select)
    },
    findUserById: (id: string, select: string = '') => {
        return userModel.findById(id).select(select)
    },
    registerUser: (user: IUser) => {
        return userModel.create(user)
    },
    findUserByConfirmationTokenAndCode: (token: string, code: string) => {
        return userModel.findOne({
            'accountConfirmation.token': token,
            'accountConfirmation.code': code
        })
    },
    findUserByPasswordResetToken: (token: string) => {
        return userModel.findOne({
            'passwordReset.token': token
        })
    },
    deleteRefreshToken: (token: string) => {
        return userModel.findOneAndUpdate(
            { 'refreshToken.token': token }, // Find user with the given refresh token
            { $set: { 'refreshToken.token': null } } // Set the token field to null
        )
    },
    getRefreshTokan: (token: string) => {
        return userModel.findOne(
            { 'refreshToken.token': token } // Find user with the given refresh token
        )
    }
}
