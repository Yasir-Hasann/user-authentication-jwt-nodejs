// module imports
const express = require('express');

// file imports
const authController = require('../controllers/auth');
const { verifyToken, verifyOptionalToken } = require('../middlewares/auth');

const router = express.Router();

router.post('/register-with-otp', authController.registerWithOTP);
router.post('/send-otp', authController.sendOTP);
router.post('/resend-otp', verifyOptionalToken, authController.resendOTP);
router.post('/verify-otp', verifyOptionalToken, authController.verifyOTP);

router.post('/register-with-link', authController.registerWithLink);
router.post('/send-link', authController.sendLink);
router.post('/resend-link', authController.resendLink);
router.get('/verify-link', authController.verifyLink);

router.patch('/change-password', verifyToken, authController.changePassword);
router.patch('/reset-password', authController.resetPassword);
router.post('/login', authController.login);
router.get('/get-profile', verifyToken, authController.getProfile);

module.exports = router;
