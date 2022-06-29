const User = require('./../models/userModel');
const catchAsync = require('./../utils/catchAsync');
const sendEmail = require('../utils/email');
const AppError = require('./../utils/appError');

const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach(el => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

//Impelmenting this to not reveal encrypted password while reading users from database.
exports.getAllUsers = catchAsync(async (req, res, next) => {
  const users = await User.find();
  //* SEND RESPONSE
  res.status(200).json({
    status: 'success',
    results: users.length,
    data: {
      users
    }
  });
});

exports.transfer = catchAsync(async (req, res, next) => {
  const { email, amount } = req.body;
  const user = await User.findOne({
    email,
    amount
  });

  if (user) {
    const Balance = user.balance - amount;

    if (Balance > 0) {
      res.status(200).json({
        success: true,
        message: 'Transaction Successful !.'
      });

      sendEmail({
        email: user.email,
        subject: 'Transaction Successfull !',
        message: `Your Transaction is been successfully sent to user:-
          ${user.email}
          and the amount is been credited to the user is:- 
          ${Balance}`
      });
    } else if (!Balance) {
      res.status(404).json({
        success: false,
        message: 'Insufficient Balance...Transaction Failed !'
      });
    }
  } else if (!user)
    return res.status(404).json({
      sucess: false,
      message: 'User not found.'
    });
});

exports.updateMe = catchAsync(async (req, res, next) => {
  // 1) Create error if user POSTs password data
  if (req.body.password || req.body.passwordConfirm) {
    return next(
      new AppError(
        'This route is not for password updates. Please use /updateMyPassword.',
        400
      )
    );
  }

  // 2) Filtered out unwanted fields names that are not allowed to be updated
  const filteredBody = filterObj(req.body, 'name', 'email');

  // 3) Update user document
  const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredBody, {
    new: true,
    runValidators: true
  });

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
});
