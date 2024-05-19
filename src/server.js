// module imports
const cors = require('cors');
require('dotenv').config();
const express = require('express');
const morgan = require('morgan');
const path = require('path');

// file imports
const connectDB = require('./config/db');
const apiRouter = require('./routes');
const errorHandler = require('./middlewares/error-handler');

// variable initializations
const app = express();
const port = process.env.PORT || 5001;

// connect mongodb
connectDB();

// middlewares
app.use('/public/', express.static(path.join('public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors());
app.use(morgan('dev'));

// mount routes
app.use('/api/v1', apiRouter);
app.use('/ping', (req, res) => {
  res.status(200).json({ success: true, message: 'Bro: I am live and working' });
});
app.use('/*', (req, res) => {
  res.status(200).json({ success: false, message: 'Invalid URL' });
});
app.use(errorHandler);

app.listen(port, () => {
  console.log(`Server is running on port: ${port}`);
});

console.log(process.env.NODE_ENV.toUpperCase());