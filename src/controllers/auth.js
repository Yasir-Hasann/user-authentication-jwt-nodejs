// module imports
const asyncHandler = require('express-async-handler');
const dayjs = require('dayjs');

// file imports
const { generateOTP, generateVerificationToken } = require('../utils/helper-methods');
const UserModel = require('../models/user');
const NodeMailer = require('../utils/node-mailer');
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
  if (!user.isEmailVerified) return next(new ErrorResponse('Account not approved', 401));

  const isMatch = await user.matchPasswords(password);
  if (!isMatch) return next(new ErrorResponse('Invalid Credentials!', 401));

  const token = user.getSignedjwtToken();
  res.status(200).json({ token, isEmailVerified: true });
});

// @desc   Register User
// @route  POST /api/v1/auth/register-otp
// @access Public
exports.registerWithOTP = asyncHandler(async (req, res, next) => {
  const user = await UserModel.create(req.body);
  if (!user) return next(new ErrorResponse('Something went wrong', 500));

  const token = user.getSignedjwtToken();
  const otp = generateOTP();
  await new NodeMailer().sendOTP(req.body.email, otp);
  await UserModel.findByIdAndUpdate(user._id, { verificationCode: otp, otpLastSentTime: dayjs().valueOf() });
  res.status(200).json({ success: true, token, message: 'Verification code is sent on email!' });
});

// @desc   Verify User with OTP
// @route  POST /api/v1/auth/verify-otp
// @access Private
exports.verifyOTP = asyncHandler(async (req, res, next) => {
  const { _id, verificationCode, otpLastSentTime } = req.user;
  const { code } = req.body;
  if (!code) return next(new ErrorResponse('code is missing in body!', 400));

  if (dayjs().diff(dayjs(otpLastSentTime)) > 500000 || verificationCode == null || otpLastSentTime == null) return next(new ErrorResponse('OTP is expired or used already!', 400));
  if (code !== verificationCode) return next(new ErrorResponse('OTP is incorrect!', 400));

  await UserModel.findByIdAndUpdate(_id, { verificationCode: null, otpLastSentTime: null, isEmailVerified: true });
  // res.redirect('/email-verified.html');
  res.status(200).json({ success: true, message: 'Profile verified!' });
});

// @desc   Resend OTP
// @route  GET /api/v1/auth/resend-otp
// @access Private
exports.resendOTPCode = asyncHandler(async (req, res, next) => {
  const { user } = req;
  if (!user) return next(new ErrorResponse('No user found!', 404));
  const otp = generateOTP();
  await new NodeMailer().sendOTP(user.email, otp);
  await UserModel.findByIdAndUpdate({ _id: user._id }, { verificationCode: otp, otpLastSentTime: dayjs().valueOf() });
  res.status(200).json({ success: true, message: 'Verification code is re-sent!' });
});

// @desc   Forget Password
// @route  GET /api/v1/auth/forget-password-otp/:email
// @access Public
exports.forgetPasswordOTP = asyncHandler(async (req, res, next) => {
  const { email } = req.params;
  if (!email) return next(new ErrorResponse('Please provide an email', 400));

  const user = await UserModel.findOne({ email });
  if (!user) return next(new ErrorResponse(`No user found with email ${email}`, 404));

  const otp = generateOTP();
  await new NodeMailer().sendOTP(user.email, otp);
  await UserModel.findByIdAndUpdate({ _id: user._id }, { verificationCode: otp, otpLastSentTime: dayjs().valueOf() });
  res.status(200).json({ success: true, message: 'Verification code sent!' });
});

// @desc   Register User
// @route  POST /api/v1/auth/register-link
// @access Public
exports.registerWithLink = asyncHandler(async (req, res, next) => {
  const user = await UserModel.create(req.body);
  if (!user) return next(new ErrorResponse('Something went wrong', 500));

  const token = user.getSignedjwtToken();
  const verificationToken = generateVerificationToken();
  await new NodeMailer().sendVerificationLink(user.email, verificationToken);
  await UserModel.findByIdAndUpdate(user._id, { verificationToken: verificationToken, linkLastSentTime: dayjs().valueOf() });
  res.status(200).json({ success: true, token, message: 'Verification link is sent on email!' });
});

// @desc   Verify User with Link
// @route  GET /api/v1/auth/verify-link
// @access Private
exports.verifyLink = asyncHandler(async (req, res, next) => {
  // const { _id, verificationToken, linkLastSentTime } = req.user;
  const { token } = req.query;
  if (!token) return next(new ErrorResponse('token is missing in query param!', 400));

  // if (dayjs().diff(dayjs(linkLastSentTime)) > 500000 || verificationToken == null || linkLastSentTime == null)
  //   return next(new ErrorResponse('Link is expired or used already!', 400));
  // if (token !== verificationToken) return next(new ErrorResponse('VerificationToken is incorrect!', 400));

  const user = await UserModel.findOneAndUpdate({ verificationToken: token }, { $set: { verificationToken: null, linkLastSentTime: null, isEmailVerified: true } }, { new: true });
  if (!user) return next(new ErrorResponse('Something went wrong', 500));

  // res.redirect('/email-verified.html');
  res.status(200).json({ success: true, message: 'Profile verified!' });
});

// @desc   Resend Link
// @route  GET /api/v1/auth/resend-link
// @access Private
exports.resendLink = asyncHandler(async (req, res, next) => {
  const { user } = req;
  if (!user) return next(new ErrorResponse('No user found!', 404));
  const verificationToken = generateVerificationToken();
  await new NodeMailer().sendVerificationLink(user.email, verificationToken);
  await UserModel.findByIdAndUpdate({ _id: user._id }, { verificationToken: verificationToken, linkLastSentTime: dayjs().valueOf() });
  res.status(200).json({ success: true, message: 'Verification link is re-sent!' });
});

// @desc   Forget Password
// @route  GET /api/v1/auth/forget-password-link/:email
// @access Public
exports.forgetPasswordLink = asyncHandler(async (req, res, next) => {
  const { email } = req.params;
  if (!email) return next(new ErrorResponse('Please provide an email', 400));

  const user = await UserModel.findOne({ email });
  if (!user) return next(new ErrorResponse(`No user found with email ${email}`, 404));

  const verificationToken = generateVerificationToken();
  await new NodeMailer().sendVerificationLink(user.email, verificationToken);
  await UserModel.findByIdAndUpdate({ _id: user._id }, { verificationToken: verificationToken, linkLastSentTime: dayjs().valueOf() });
  res.status(200).json({ success: true, message: 'Verification link sent!' });
});

// @desc   Change Password
// @route  POST /api/v1/auth/change-password
// @access Private
exports.changePassword = asyncHandler(async (req, res, next) => {
  const { _id } = req.user;

  const { password, oldPassword } = req.body;
  if (!password || !oldPassword) return next(new ErrorResponse('field `password`, `oldPassword` is required', 404));

  const user = await UserModel.findById(_id).select('+password');
  if (!user) return next(new ErrorResponse("Password couldn't be updated at this moment", 500));

  const isMatch = await user.matchPasswords(oldPassword);
  if (!isMatch) return next(new ErrorResponse('Invalid Old Password!', 401));

  const hashedPass = await user.setPassword(password);
  const save = await UserModel.findByIdAndUpdate(_id, { password: hashedPass });
  if (!save) return next(new ErrorResponse("Password couldn't be updated at this moment", 500));

  res.status(200).json({ success: true, message: 'Password Change Success!' });
});

// @desc   Reset Password
// @route  POST /api/v1/auth/reset-password
// @access Private
exports.resetPassword = asyncHandler(async (req, res, next) => {
  const { _id } = req.user;
  const { password } = req.body;
  if (!password) return next(new ErrorResponse('field `password` is required', 404));

  const user = await UserModel.findById(_id).select('+password');
  if (!user) return next(new ErrorResponse('Something went wrong', 500));

  const hashedPass = await user.setPassword(password);
  const save = await UserModel.findByIdAndUpdate(_id, { password: hashedPass });
  if (!save) return next(new ErrorResponse('Something went wrong', 500));

  res.status(200).json({ success: true, message: 'Password Reset was successful!' });
});

// @desc   Get user
// @route  GET /api/v1/auth/whoami
// @access Private
exports.whoami = asyncHandler(async (req, res) => {
  const { createdAt, updatedAt, __v, verificationCode, otpLastSentTime, verificationToken, linkLastSentTime, ...rest } = req.user._doc;
  res.status(200).send({ ...rest });
});
