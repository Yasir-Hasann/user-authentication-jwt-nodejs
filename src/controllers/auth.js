// module imports
const asyncHandler = require('express-async-handler');
const dayjs = require('dayjs');

// file imports
const { generateOTP, generateVerificationToken } = require('../utils/helper-methods');
const UserModel = require('../models/user');
const nodeMailer = require('../utils/node-mailer');
const ErrorResponse = require('../utils/error-response');

// @desc   Login User
// @route  POST /api/v1/auth/login
// @access Public
exports.login = asyncHandler(async (req, res, next) => {
  const { email, password } = req.body;
  if (!email || !password) return next(new ErrorResponse('Please provide an email and password', 400));

  const user = await UserModel.findOne({ email }).select('+password');
  if (!user) return next(new ErrorResponse('Invalid Credentials!', 401));

  if (user.isBlocked) return next(new ErrorResponse('Account blocked! contact administrator', 401));
  if (!user.isEmailVerified) return next(new ErrorResponse('Email not verified', 401));

  const isMatch = await user.matchPasswords(password);
  if (!isMatch) return next(new ErrorResponse('Invalid Credentials!', 401));

  const token = user.getSignedJwtToken();
  res.status(200).json({ success: true, message: 'User logged in successfully', token });
});

// @desc   Register User With OTP
// @route  POST /api/v1/auth/register-with-otp
// @access Public
exports.registerWithOTP = asyncHandler(async (req, res, next) => {
  const { name, email, password, isMobile = false } = req.body;
  if (!name || !email || !password) return next(new ErrorResponse('Please provide a name, email and password', 400));

  const userExists = await UserModel.findOne({ email });
  if (userExists) return next(new ErrorResponse('Email already exists', 400));

  const user = await UserModel.create(req.body);
  if (!user) return next(new ErrorResponse('Something went wrong', 500));

  const otp = generateOTP();
  await UserModel.findByIdAndUpdate(user._id, { verificationCode: otp, otpLastSentTime: dayjs().valueOf() });

  await nodeMailer.sendOTP(email, otp);
  if (isMobile) {
    const token = user.getSignedJwtToken();
    return res.status(200).json({ success: true, token, message: 'Verification code is sent on email!' });
  }

  res.status(200).json({ success: true, message: 'Verification code is sent on email!' });
});

// @desc   Send OTP (forget-password, reset-password)
// @route  POST /api/v1/auth/send-otp
// @access Public
exports.sendOTP = asyncHandler(async (req, res, next) => {
  const { email } = req.body;
  if (!email) return next(new ErrorResponse('Please provide an email', 400));

  const user = await UserModel.findOne({ email });
  if (!user) return next(new ErrorResponse(`No user found with email ${email}`, 404));

  const otp = generateOTP();
  await nodeMailer.sendOTP(user.email, otp);

  await UserModel.findByIdAndUpdate(user._id, { verificationCode: otp, otpLastSentTime: dayjs().valueOf() });
  res.status(200).json({ success: true, message: 'Verification code sent!' });
});

// @desc   Resend OTP
// @route  POST /api/v1/auth/resend-otp
// @access Public/Private
exports.resendOTP = asyncHandler(async (req, res, next) => {
  const { isMobile = false } = req.body;

  let user = null;
  if (isMobile) {
    user = req.user;
    if (!user) return next(new ErrorResponse('No user found!', 404));
  } else {
    const { email } = req.body;
    if (!email) return next(new ErrorResponse('Email is required!', 400));

    user = await UserModel.findOne({ email });
    if (!user) return next(new ErrorResponse(`No user found with email ${email}`, 404));
  }

  const otp = generateOTP();
  await nodeMailer.sendOTP(user.email, otp);

  await UserModel.findByIdAndUpdate(user._id, { verificationCode: otp, otpLastSentTime: dayjs().valueOf() });
  res.status(200).json({ success: true, message: 'Verification code is re-sent!' });
});

// @desc   Verify OTP
// @route  POST /api/v1/auth/verify-otp
// @access Public/Private
exports.verifyOTP = asyncHandler(async (req, res, next) => {
  const { code, isMobile = false } = req.body;
  if (!code) return next(new ErrorResponse('Code is required!', 400));

  if (isMobile) {
    const { _id, verificationCode, otpLastSentTime } = req.user;
    if (dayjs().diff(dayjs(otpLastSentTime)) > 500000 || verificationCode == null || otpLastSentTime == null) return next(new ErrorResponse('OTP is expired or used already!', 400));
    if (code !== verificationCode) return next(new ErrorResponse('OTP is incorrect!', 400));
    await UserModel.findByIdAndUpdate(_id, { verificationCode: null, otpLastSentTime: null, isEmailVerified: true });
    return res.status(200).json({ success: true, message: 'OTP verified successfully!' });
  } else {
    const user = await UserModel.findOne({ verificationCode: code });
    if (!user) return next(new ErrorResponse('OTP is incorrect!', 400));

    const { _id, verificationCode, otpLastSentTime } = user;
    if (dayjs().diff(dayjs(otpLastSentTime)) > 500000 || verificationCode == null || otpLastSentTime == null) return next(new ErrorResponse('OTP is expired or used already!', 400));
    await UserModel.findByIdAndUpdate(_id, { verificationCode: null, otpLastSentTime: null, isEmailVerified: true });
    return res.redirect('/email-verified.html');
  }
});

// @desc   Register User With Verification Link
// @route  POST /api/v1/auth/register-link
// @access Public
exports.registerWithLink = asyncHandler(async (req, res, next) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return next(new ErrorResponse('Please provide a name, email and password', 400));

  const userExists = await UserModel.findOne({ email });
  if (userExists) return next(new ErrorResponse('Email already exists', 400));

  const user = await UserModel.create(req.body);
  if (!user) return next(new ErrorResponse('Something went wrong', 500));

  const verificationToken = generateVerificationToken();
  await nodeMailer.sendVerificationLink(user.email, verificationToken);

  await UserModel.findByIdAndUpdate(user._id, { verificationToken: verificationToken, linkLastSentTime: dayjs().valueOf() });
  res.status(200).json({ success: true, message: 'Verification link is sent on email!' });
});

// @desc   Send Link (forget-password, reset-password)
// @route  POST /api/v1/auth/send-link
// @access Public
exports.sendLink = asyncHandler(async (req, res, next) => {
  const { email } = req.body;
  if (!email) return next(new ErrorResponse('Email is required', 400));

  const user = await UserModel.findOne({ email });
  if (!user) return next(new ErrorResponse(`No user found with email ${email}`, 404));

  const verificationToken = generateVerificationToken();
  await nodeMailer.sendVerificationLink(user.email, verificationToken);

  await UserModel.findByIdAndUpdate(user._id, { verificationToken: verificationToken, linkLastSentTime: dayjs().valueOf() });
  res.status(200).json({ success: true, message: 'Verification link sent!' });
});

// @desc   Resend Link
// @route  POST /api/v1/auth/resend-link
// @access Public
exports.resendLink = asyncHandler(async (req, res, next) => {
  const { email } = req.body;
  if (!email) return next(new ErrorResponse('Email is required', 400));

  const user = await UserModel.findOne({ email });
  if (!user) return next(new ErrorResponse(`No user found with email ${email}`, 404));

  const verificationToken = generateVerificationToken();
  await nodeMailer.sendVerificationLink(user.email, verificationToken);

  await UserModel.findByIdAndUpdate(user._id, { verificationToken: verificationToken, linkLastSentTime: dayjs().valueOf() });
  res.status(200).json({ success: true, message: 'Verification link is re-sent!' });
});

// @desc   Verify Link
// @route  GET /api/v1/auth/verify-link
// @access Public
exports.verifyLink = asyncHandler(async (req, res, next) => {
  const { token } = req.query;
  if (!token) return next(new ErrorResponse('Token is required!', 400));

  const user = await UserModel.findOne({ verificationToken: token });
  if (!user) return next(new ErrorResponse('Invalid token!', 400));

  await UserModel.findByIdAndUpdate(user._id, { $set: { verificationToken: null, linkLastSentTime: null, isEmailVerified: true } });
  res.redirect('/email-verified.html');
});

// @desc   Change Password
// @route  PATCH /api/v1/auth/change-password
// @access Private
exports.changePassword = asyncHandler(async (req, res, next) => {
  const { oldPassword, newPassword } = req.body;
  if (!oldPassword || !newPassword) return next(new ErrorResponse('field `oldPassword`, `newPassword` is required', 400));

  const user = await UserModel.findById(req.user._id).select('+password');
  if (!user) return next(new ErrorResponse("Password couldn't be updated at this moment", 500));

  const isMatch = await user.matchPasswords(oldPassword);
  if (!isMatch) return next(new ErrorResponse('Invalid Old Password!', 401));

  const hashedPass = await user.setPassword(newPassword);
  await UserModel.findByIdAndUpdate(user._id, { password: hashedPass });

  res.status(200).json({ success: true, message: 'Your password has been changed successfully!' });
});

// @desc   Reset Password
// @route  PATCH /api/v1/auth/reset-password
// @access Public
exports.resetPassword = asyncHandler(async (req, res, next) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword) return next(new ErrorResponse('field `token`, `newPassword` is required', 404));

  const user = await UserModel.findOne({ verificationToken: token }).select('+password');
  if (!user) return next(new ErrorResponse('Invalid token', 400));

  const hashedPass = await user.setPassword(newPassword);
  await UserModel.findByIdAndUpdate(user._id, { password: hashedPass, verificationToken: null, linkLastSentTime: null });

  res.status(200).json({ success: true, message: 'Your password has been reset successfully!' });
});

// @desc   Get user
// @route  GET /api/v1/auth/get-profile
// @access Private
exports.getProfile = asyncHandler(async (req, res) => {
  const { createdAt, updatedAt, __v, verificationCode, otpLastSentTime, verificationToken, linkLastSentTime, ...rest } = req.user._doc;
  res.status(200).json({ ...rest });
});
