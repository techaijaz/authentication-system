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
    findUserByEmail: (email: string) => {
        return userModel.findOne({ email })
    },
    registerUser: (user: IUser) => {
        return userModel.create(user)
    }
}
