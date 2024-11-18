export default {
    SUCCESS: 'The opration has been successful',
    ERROR: 'The opration has an error',
    NOT_FOUND: (entity: string) => `${entity} not found`,
    TOO_MANY_REQUEST: 'Too many request please try again later',
    INCORECT_PHONE_NUMBER: 'Incorect phone number',
    ALREADY_EXIST: (entity: string, identifire: string) => {
        return `${entity} is already exist with ${identifire}`
    }
}
