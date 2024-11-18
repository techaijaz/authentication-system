import Joi from 'joi'
import { IRegisterRequestBody } from '../types/userTypes'

export const validationRegisterBody = Joi.object<IRegisterRequestBody>({
    name: Joi.string().required().min(3).max(72).trim(),
    email: Joi.string().email().required(),
    phone: Joi.string().min(4).max(20).required(),
    password: Joi.string().min(8).max(72).required().trim(),
    //.regex(/^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/),
    consent: Joi.boolean().required().valid(true)
})

export const validateJoiSchema = <T>(schema: Joi.Schema, value: unknown) => {
    const result = schema.validate(value)
    return {
        value: result.value as T,
        error: result.error?.message
    }
}
