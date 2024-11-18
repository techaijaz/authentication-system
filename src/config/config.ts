import dotenvFlow from 'dotenv-flow'

dotenvFlow.config()

export default {
    //genral
    ENV: process.env.NODE_ENV,
    PORT: process.env.PORT,
    SERVER_URL: process.env.SERVER_URL,

    //Database
    DATABASE_URL: process.env.DATABASE_URL,

    //fruntend
    FRONTEND_URL: process.env.FRONTEND_URL,

    //email service
    EMAIL_SERVICE_API_KEY: process.env.EMAIL_SERVICE_API_KEY
}
