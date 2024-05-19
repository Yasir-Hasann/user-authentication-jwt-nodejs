// module imports
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  host: 'smtp.gmail.com',
  port: 587,
  auth: {
    user: process.env.SMTP_EMAIL,
    pass: process.env.SMTP_PASS,
  },
});

class NodeMailer {
  constructor() {
    this.transporter = transporter;
  }

  async sendEmail(email, html, subject) {
    try {
      await this.transporter.sendMail({ from: process.env.SMTP_EMAIL, to: email, html, subject });
    } catch (error) {
      console.error('Error sending email:', error);
    }
  }

  async sendOTP(email, otp) {
    let html = `<div>
              <h1>${otp}</h1>
          </div>
      </html>`;
    await this.sendEmail(email, html, 'Verify Account');
  }

  async sendVerificationLink(email, verificationToken) {
    const verificationLink = `${process.env.BASE_URL}auth/verify-link?token=${verificationToken}`;
    const html = `<div style="font-family: 'Arial', sans-serif; background-color: #f4f4f4; padding: 20px; border-radius: 8px;">
              <p style="font-size: 16px; color: #333;">Click the following link to verify your email:</p>
              <a href="${verificationLink}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: #fff; text-decoration: none; border-radius: 4px;">Verify Now</a>
            </div>`;

    await this.sendEmail(email, html, 'Verify Account');
  }
}

module.exports = NodeMailer;
