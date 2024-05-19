// module imports
const express = require('express');

// file imports
const authController = require('../controllers/auth');
const { verifyToken } = require('../middlewares/auth');

const router = express.Router();

router.post('/register-otp', authController.registerWithOTP);
router.post('/verify-otp', verifyToken, authController.verifyOTP);
router.get('/resend-otp', verifyToken, authController.resendOTPCode);
router.get('/forget-password-otp/:email', authController.forgetPasswordOTP);

router.post('/register-link', authController.registerWithLink);
router.get('/verify-link', authController.verifyLink);
router.get('/resend-link', verifyToken, authController.resendLink);
router.get('/forget-password-link/:email', authController.forgetPasswordLink);

router.post('/change-password', verifyToken, authController.changePassword);
router.post('/reset-password', verifyToken, authController.resetPassword);
router.post('/login', authController.login);
router.get('/whoami', verifyToken, authController.whoami);

module.exports = router;
