// module imports
const express = require('express');

// file imports
const auth = require('./auth');

// variable initializations
const router = express.Router();

router.use('/auth', auth);

module.exports = router;
