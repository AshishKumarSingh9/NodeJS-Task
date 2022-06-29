const crypto = require('crypto');
const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const AppError = require('./../utils/appError');
const sendEmail = require('./../utils/email');
const sendTransaction = require('./../blockchain/send');
const newAccount = require('./../blockchain/newAccount');
const restoreWallet = require('./../blockchain/restoreWallet');

// Separate function to sign the token, this will have 'id' as the only argument.
const signToken = id => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    //Using ES6 syntax for 'id' instead of { id: newUser._id }
    expiresIn: process.env.JWT_EXPIRES_IN
  });
};

const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true
  };
  if (process.env.NODE_ENV === 'production') cookieOptions.secure = true;

  res.cookie('jwt', token, cookieOptions);

  // Remove password from output
  user.password = undefined;

  res.status(statusCode).json({
    status: 'success',
    token,
    data: {
      user
    }
  });
};

exports.restore = catchAsync(async (req, res, next) => {
  restoreWallet(req.body.seedPhrase)
    .then(() => process.exit(0))
    .catch(error => {
      console.error(error);
      process.exit(1);
    });

  res.status(201).json({
    status: 'success'
  });
});

exports.transaction = catchAsync(async (req, res, next) => {
  sendTransaction(req.body.receiverAddress, req.body.ethAmount)
    .then(() => process.exit(0))
    .catch(error => {
      console.error(error);
      process.exit(1);
    });
});

exports.verifyEmail = catchAsync(async (req, res, next) => {
  // 1) Get user based on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    emailVerficationToken: hashedToken,
    emailVerficationExpires: { $gt: Date.now() }
  });

  // 2) If token has not expired, and there is user, set the new password
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }
  user.emailVerified = true;
  await user.save();

  createSendToken(user, 200, res);
});

exports.emailVerification = catchAsync(async (req, res, next) => {
  // 1) Get user based on POSTed email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError('There is no user with email address.', 404));
  }

  // 2) Generate the random reset token
  const verificationToken = user.createEmailVerficationToken();
  await user.save({ validateBeforeSave: false });

  // 3) Send it to user's email
  const verificationURL = `${req.protocol}://${req.get(
    'host'
  )}/api/v1/users/verifyEmail/${verificationToken}`;

  const message = `Welcome to your wallet! Submit a PATCH request by clicking the following URL: ${verificationURL}.\nIf you didn't sign up, please ignore this email!`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'Your email verification token (valid for 10 min)',
      message
    });

    res.status(200).json({
      status: 'success',
      message: 'email verification token sent to email!'
    });
  } catch (err) {
    user.emailVerficationToken = undefined;
    user.emailVerficationExpires = undefined;
    user.emailVerified = false;
    await user.save({ validateBeforeSave: false });

    return next(
      new AppError('There was an error sending the email. Try again later!'),
      500
    );
  }
});

exports.signup = catchAsync(async (req, res, next) => {
  // only these defined fields can be used in the body of the request now.
  const newUser = await User.create({
    userName: req.body.userName,
    email: req.body.email,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
    balance: req.body.balance
  });

  newAccount(req)
    .then(() => process.exit(0))
    .catch(error => {
      console.error(error);
      process.exit(1);
    });

  //Signing the token using the 'sign' method on 'jwt'.
  const token = signToken(newUser._id);

  res.status(201).json({
    status: 'success',
    token, //sending to the client.
    data: {
      user: newUser
    }
  });
});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  // 1) Check if email and password exist
  if (!email || !password) {
    //If the email or password is wrong, send an error.
    return next(new AppError('Please provide email and password!', 400));
  }
  // 2) Check if user exists && password is correct
  const user = await User.findOne({ email }).select('+password');

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError('Incorrect email or password', 401));
  }

  //* 3) If everything ok, send token to client
  const token = signToken(user._id);

  res.status(200).json({
    status: 'success',
    token
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  //* 1) Getting token and check of it's there

  let token;

  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {
    return next(
      new AppError('You are not logged in! Please log in to get access.', 401)
    );
  }

  //* 2) Token Verification
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  //* 3) Check if user still exists
  const currentUser = await User.findById(decoded.id); // Getiing 'id' from the decoded token.
  if (!currentUser) {
    return next(
      new AppError(
        'The user belonging to this token does no longer exist.',
        401
      )
    );
  }

  //* 4) Check if user changed password after the token was issued
  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(
      new AppError('User recently changed password! Please log in again.', 401)
    );
  }

  // GRANT ACCESS TO PROTECTED ROUTE
  req.user = currentUser; //putting entire user data on the request.

  next();
});

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on POSTed email
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return next(new AppError('There is no user with email address.', 404));
  }

  // 2) Generate the random reset token
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  // 3) Send it to user's email
  const resetURL = `${req.protocol}://${req.get(
    'host'
  )}/api/v1/users/resetPassword/${resetToken}`;

  const message = `Forgot your password? Submit a PATCH request with your new password and passwordConfirm to: ${resetURL}.\nIf you didn't forget your password, please ignore this email!`;

  try {
    await sendEmail({
      email: user.email,
      subject: 'Your password reset token (valid for 10 min)',
      message
    });

    res.status(200).json({
      status: 'success',
      message: 'Token sent to email!'
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(
      new AppError('There was an error sending the email. Try again later!'),
      500
    );
  }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // 1) Get user based on the token
  const hashedToken = crypto
    .createHash('sha256')
    .update(req.params.token)
    .digest('hex');

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }
  });

  // 2) If token has not expired, and there is user, set the new password
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  // 3) Update changedPasswordAt property for the user
  // 4) Log the user in, send JWT
  createSendToken(user, 200, res);
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  // 1) Get user from collection
  const user = await User.findById(req.user.id).select('+password');

  // 2) Check if POSTed current password is correct
  if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
    return next(new AppError('Your current password is wrong.', 401));
  }

  // 3) If so, update password
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  await user.save();
  // User.findByIdAndUpdate will NOT work as intended!

  // 4) Log user in, send JWT
  createSendToken(user, 200, res);
});

/*

{
    "userName":"ashish",
    "email":"hello@ashish.io",
    "password":"pass1234",
    "passwordConfirm":"pass1234",
    "balance": "1000"
}

*/
