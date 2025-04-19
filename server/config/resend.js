import { Resend } from 'resend';
import generateWelcomeEmail from '../email/generateWelcomeEmail';

const resend = new Resend(process.env.RESEND_API_KEY);

export async function welcomeEmail(to, name, loginUrl) {
    try {
        const result = await resend.emails.send({
            from: 'Auth Template MERN <noreply@yashh1524.com>',
            to,
            subject: "Welcome to Auth Template",
            html: generateWelcomeEmail(name, loginUrl),
        });

        return result;
    } catch (err) {
        console.error('Reminder Email error:', err);
        throw err;
    }
}