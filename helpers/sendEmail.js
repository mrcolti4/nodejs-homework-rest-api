import nodemailer from "nodemailer";
import "dotenv/config";

const { GMAIL_EMAIL, GMAIL_PASSWORD } = process.env;

const nodemailerConfig = {
  service: "Gmail",
  secure: true,
  auth: {
    user: GMAIL_EMAIL,
    pass: GMAIL_PASSWORD,
  },
};

const transoprt = nodemailer.createTransport(nodemailerConfig);

const sendEmail = (data) => {
  const email = { ...data, from: GMAIL_EMAIL };

  return transoprt.sendMail(email);
};

export default sendEmail;
