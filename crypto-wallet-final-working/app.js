const express = require('express');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');

const userRouter = require('./routes/userRoutes');

const app = express();

//* Set security HTTP headers
app.use(helmet());

if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev'));
}

const limiter = rateLimit({
  max: 100, //max allowed requests in a time window.
  windowMs: 60 * 60 * 1000, //time window in milliseconds, setting to 1 hour here.
  message: 'Too many requests from this IP, please try again in an hour!'
});
app.use('/api', limiter);

//* Body parser, reading data from body into req.body
app.use(express.json({ limit: '10kb' })); //limiting the amount of data that comes in the body of the request. Body larger than 10kb will not be accepted.

app.use(express.json());
app.use(express.static(`${__dirname}/public`));

//* ROUTES
app.use('/users', userRouter);

app.get('/', (req, res) => {
  res.sendFile(`${__dirname}/public/index.html`);
});

app.use('/api/v1/users', userRouter);

app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

module.exports = app;
