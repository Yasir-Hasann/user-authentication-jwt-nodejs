// module imports
const otpGenerator = require('otp-generator');
const crypto = require('crypto');

exports.generateOTP = () => otpGenerator.generate(6, { lowerCaseAlphabets: false, upperCaseAlphabets: false, specialChars: false });
exports.generateVerificationToken = () => crypto.randomBytes(20).toString('hex');
