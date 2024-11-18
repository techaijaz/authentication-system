import { Resend } from 'resend'
import config from '../config/config'

const resend = new Resend(config.EMAIL_SERVICE_API_KEY)

export default {
    sendEmail: async (to: string[], subject: string, text: string) => {
        try {
            //console.log(to, subject, text)
            const result = await resend.emails.send({
                from: 'onboarding@resend.dev',
                to,
                subject,
                html: text
            })

            return result
        } catch (error) {
            throw error
        }
    }
}
