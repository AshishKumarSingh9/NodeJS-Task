const mongoose = require('mongoose');
const validator = require('validator'); // to validate the emails
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

//create schema
const userSchema = new mongoose.Schema({
  userName: {
    type: String,
    required: [true, 'Please tell us your name!']
  },
  email: {
    type: String,
    required: [true, 'Please provide your email'],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email!']
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 8,
    select: false
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      //* Custom validator
      // This only works on CREATE and SAVE!!!
      validator: function(el) {
        return el === this.password;
      },
      message: 'Passwords are not the same!'
    }
  },
  balance: Number,
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  walletAddress: String,
  seedPhrase: String,
  emailVerficationToken: String,
  emailVerficationExpires: Date,
  emailVerified: {
    type: Boolean,
    default: false
  }
});

userSchema.pre('save', async function(next) {
  // Only run this function if password was actually modified
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);

  // Delete passwordConfirm field
  this.passwordConfirm = undefined;
  next();
});

userSchema.pre('save', function(next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;
  next();
});

userSchema.methods.correctPassword = async function(
  candidatePassword,
  userPassword
) {
  return await bcrypt.compare(candidatePassword, userPassword); //Using compare function on 'bcrypt'
};

userSchema.methods.changedPasswordAfter = function(JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(
      //parsing into a int value.
      this.passwordChangedAt.getTime() / 1000, //converting the milliseconds to seconds
      10 //specifying the base. Here the base is 10.
    );

    return JWTTimestamp < changedTimestamp; // If JWTTimestamp = 100 < changedTimestamp = 200 . This will return true, that means changed. If JWTTimestamp = 500 < changedTimestamp = 100 . This will return false, that means NOT changed.
  }

  // False means NOT changed. This is default return of this function.
  return false;
};

userSchema.methods.createPasswordResetToken = function() {
  const resetToken = crypto.randomBytes(32).toString('hex'); //using the built-in 'crypto' module's 'randomBytes' method to generate a random number, then converting it to a hexadecimal string.

  this.passwordResetToken = crypto
    .createHash('sha256')
    .update(resetToken)
    .digest('hex');

  this.passwordResetExpires = Date.now() + 10 * 60 * 1000; // setting the time limit for reset token as 10 minutes.

  return resetToken; //returning the plain text token, so as to send it via email.
};

userSchema.methods.createEmailVerficationToken = function() {
  const emailVerificationToken = crypto.randomBytes(32).toString('hex');

  this.emailVerficationToken = crypto
    .createHash('sha256')
    .update(emailVerificationToken)
    .digest('hex');

  this.emailVerficationExpires = Date.now() + 10 * 60 * 1000;

  return emailVerificationToken;
};

//Crating model from schema
const User = mongoose.model('User', userSchema);

module.exports = User;
