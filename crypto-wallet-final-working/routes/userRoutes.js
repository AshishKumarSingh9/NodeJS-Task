const express = require('express');
// const userController = require('./../controllers/userController');
const authController = require('./../controllers/authController');
const userController = require('./../controllers/userController');

const router = express.Router();

router.post('/signup', authController.signup, authController.emailVerification);
router.post('/restore', authController.restore);
router.post('/sendTransaction', authController.transaction);
router.post('/login', authController.login);
router.post('/forgotPassword', authController.forgotPassword);
router.patch('/resetPassword/:token', authController.resetPassword);
router.patch('/verifyEmail/:token', authController.verifyEmail);

router.patch(
  '/updateMyPassword',
  authController.protect,
  authController.updatePassword
);
router.patch('/updateMe', authController.protect, userController.updateMe);

router.route('/').get(userController.getAllUsers);
//   .post(userController.createUser);

router.route('/').get(authController.protect, userController.transfer);

// router
//   .route('/:id')
//   .get(userController.getUser)
//   .patch(userController.updateUser)
//   .delete(userController.deleteUser);

module.exports = router;
