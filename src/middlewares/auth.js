// module imports
const jwt = require('jsonwebtoken');
const asyncHandler = require('express-async-handler');

// file imports
const UserModel = require('../models/user');

exports.verifyToken = asyncHandler(async (req, res, next) => {
  const token = (req.headers.authorization && req.headers.authorization.split('Bearer')[1]) || (req.signedCookies && req.signedCookies.jwt) || (req.cookies && req.cookies.jwt);

  if (!token) return res.status(401).send('Unauthorized: No token provided');

  try {
    // Verify Token
    const verify = jwt.verify(token.trim(), process.env.JWT_SECRET);

    // Get User from Token
    const user = await UserModel.findById(verify._id).select('-password');

    if (!user) return res.status(401).send('unauthorized');

    // Attach user to the request object
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).send('Unauthorized: Invalid token');
  }
});
