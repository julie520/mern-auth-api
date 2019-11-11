const router = require("express").Router();

// import controller
const {
  signup,
  signupWithConfirm,
  accountActivation,
  signin,
  forgotPassword,
  resetPassword,
  googleLogin,
  facebookLogin
} = require("../controllers/auth");

// import validator
const {
  userSignupValidator,
  userSigninValidator,
  forgotPasswordValidator,
  resetPasswordValidator
} = require("../validators/auth");
const { runValidation } = require("../validators");

router.post("/signup", userSignupValidator, runValidation, signup);
router.post("/account-activation", accountActivation);
router.post("/signin", userSigninValidator, runValidation, signin);
router.post(
  "/signupWithConfirm",
  userSignupValidator,
  runValidation,
  signupWithConfirm
);

//forgot reset password
router.put(
  "/forgot-password",
  forgotPasswordValidator,
  runValidation,
  forgotPassword
);

router.put(
  "/reset-password",
  resetPasswordValidator,
  runValidation,
  resetPassword
);

router.post("/google-login", googleLogin);
router.post("/facebook-login", facebookLogin);
module.exports = router;
