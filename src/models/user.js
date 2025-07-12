// module imports
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const UserSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true, select: false },
    isBlocked: { type: Boolean, default: false },
    isEmailVerified: { type: Boolean, default: false },
    verificationCode: String,
    otpLastSentTime: Number,
    verificationToken: String,
    linkLastSentTime: Number,
  },
  {
    timestamps: true,
  }
);

UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

UserSchema.methods.setPassword = async function (newPass) {
  const salt = await bcrypt.genSalt(10);
  const pass = await bcrypt.hash(newPass, salt);
  return pass;
};

UserSchema.methods.getSignedJwtToken = function () {
  return jwt.sign({ _id: this._id, type: 'user' }, process.env.JWT_SECRET);
};

UserSchema.methods.matchPasswords = async function (enteredPassword) {
  const isMatched = await bcrypt.compare(enteredPassword, this.password);
  return isMatched;
};

module.exports = mongoose.model('user', UserSchema);
