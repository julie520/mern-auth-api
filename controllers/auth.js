const User = require("../models/user");
const jwt = require("jsonwebtoken");
const expressJwt = require("express-jwt");
const _ = require("lodash");
const { OAuth2Client } = require("google-auth-library");
const fetch = require("node-fetch");

// sendgrig
const sgMail = require("@sendgrid/mail");
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

exports.signup = (req, res) => {
  // console.log("REQ BODY ON SIGNUP", req.body);
  const { name, email, password } = req.body;

  User.findOne({ email }).exec((err, user) => {
    if (user) {
      return res.status(400).json({
        error: "Email is taken"
      });
    }
  });

  let newUser = new User({ name, email, password });
  newUser.save((err, success) => {
    if (err) {
      console.log("SIGNUP ERROR", err);
      return res.status(400).json({
        error: "Error saving user in database. Try signup again"
      });
    }
    res.json({
      message: "Signup success! Please signin"
    });
  });
};

/**
 * if you used above approach signup user in real world app
 * email confirmation
 * email send the user signup information encoded in jwt
 * there will also be a url link
 */
exports.signupWithConfirm = (req, res) => {
  const { name, email, password } = req.body;

  User.findOne({ email }).exec((err, user) => {
    if (user) {
      return res.status(400).json({
        error: "Email is taken"
      });
    }

    const token = jwt.sign(
      { name, email, password },
      process.env.JWT_ACCOUNT_ACTIVATION,
      { expiresIn: "1d" }
    );

    const emailData = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: `Account activation link`,
      html: `
          <h1>Please use the following link to activate your account</h1>
          <p>${process.env.CLIENT_URL}/auth/activate/${token}</p>
          <hr/>
          <p>This email may contain sensitive information</p>
          <p>${process.env.CLIENT_URL}</p>
      `
    };

    sgMail
      .send(emailData)
      .then(sent => {
        console.log("SIGNUP EMAIL SENT", sent);
        return res.json({
          message: `EMAIL has been sent to ${email}. Following the instruction to activated your account`
        });
      })
      .catch(err => {
        console.log("SIGNUP EMAIL SENT ERROR", sent);
        return res.status(500).json({
          error: err.message
        });
      });
  });
};

exports.accountActivation = (req, res) => {
  const { token } = req.body;

  if (token) {
    jwt.verify(token, process.env.JWT_ACCOUNT_ACTIVATION, function(
      err,
      decoded
    ) {
      if (err) {
        console.log("JWT VERIFY IN ACCOUNT ACTIVATION ERROR", err);
        return res.status(401).json({
          error: "Expired link. Signup again"
        });
      }

      const { name, email, password } = decoded;

      User.findOne({ email }).exec((err, user) => {
        if (user) {
          return res.json({
            message: "Your are already activated. Please signin"
          });
        }
      });

      let newUser = new User({ name, email, password });
      newUser.save((err, success) => {
        if (err) {
          console.log("SAVE USER IN ACCOUNT ACTIVATION ERROR", err);
          return res.status(401).json({
            error: "Error saving user in database. Try signup again"
          });
        }
        res.json({
          message: "Signup success! Please signin"
        });
      });
    });
  } else {
    return res.status(400).json({
      error: "Something went wrong. Try signup again"
    });
  }
};

exports.signin = (req, res) => {
  const { email, password } = req.body;
  User.findOne({ email }).exec((err, user) => {
    if (err || !user) {
      return res.status(400).json({
        error: "User with that email does not exist. Please signup"
      });
    }

    // authenticate password
    if (!user.authenticate(password)) {
      return res.status(400).json({
        error: "Email and password do not match"
      });
    }

    // generate a token and send to client
    const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "3h"
    });
    const { _id, name, email, role } = user;

    res.json({ token, user: { _id, name, email, role } });
  });
};

exports.authMiddleware = expressJwt({ secret: process.env.JWT_SECRET }); //req.user._id

exports.adminMiddleware = (req, res, next) => {
  User.findById(req.user._id, { hashedPassword: 0, salt: 0 }).exec(
    (err, user) => {
      if (err || !user) {
        return res.status(404).json({
          error: "User not found"
        });
      }

      if (user.role !== "admin") {
        return res.status(403).json({
          error: "Unauthorized access"
        });
      }

      req.profile = user;
      next();
    }
  );
};

exports.forgotPassword = (req, res) => {
  const { email } = req.body;
  console.log(email);

  User.findOne({ email }, { hashedPassword: 0, salt: 0 })
    .then(user => {
      if (!user) {
        return res.status(404).json({
          error: "User with that email does not exist"
        });
      }

      const token = jwt.sign(
        { name: user.name },
        process.env.JWT_RESET_PASSWORD,
        {
          expiresIn: "10m"
        }
      );

      const emailData = {
        from: process.env.EMAIL_FROM,
        to: email,
        subject: "Password Reset link",
        html: `
        <h1>Please use the following link to reset your password</h1>
        <p>${process.env.CLIENT_URL}/auth/password/reset/${token}</p>
        <hr/>
        <p>This email may contain sensitive information</p>
        <p>${process.env.CLIENT_URL}</p>
        `
      };

      return user.updateOne({ resetPasswordLink: token }, (err, success) => {
        if (err) {
          console.log("resetPasswordLink ERROR", err);
          return status(500).json({
            error: "Database connection error on user password forgot request"
          });
        }

        sgMail
          .send(emailData)
          .then(sent => {
            console.log("FORGOT PASSWORD EMAIL SENT", sent);
            return res.json({
              message: `Email has been sent to ${email}. `
            });
          })
          .catch(err => {
            console.log("FORGOT PASSWORD EMAIL SENT ERROR", err);
            return res.status(500).json({
              error: err.message
            });
          });
      });
    })
    .catch(err => {
      console.log("FORGOT PASSWORD ERROR", err);
      return res.status(404).json({
        error: "User with that email does not exist"
      });
    });
};

exports.resetPassword = (req, res) => {
  const { resetPasswordLink, newPassword } = req.body;
  if (resetPasswordLink) {
    jwt.verify(resetPasswordLink, process.env.JWT_RESET_PASSWORD, function(
      err,
      decoded
    ) {
      if (err) {
        return res.status(401).json({
          error: "Expired link, Try again"
        });
      }

      User.findOne({ resetPasswordLink }, (err, user) => {
        if (err || !user) {
          return res.status(404).json({
            error: "User not found"
          });
        }
        const updateFields = {
          password: newPassword,
          resetPasswordLink: ""
        };

        user = _.extend(user, updateFields);
        user.save((err, result) => {
          if (err) {
            console.log("RESET PASSWORD UPDATE ERROR", err);
            return res.status(500).json({
              error: "Error resetting user password"
            });
          }
          res.json({
            message: "Great! Now you can login with your new password"
          });
        });
      });
    });
  }
};

exports.googleLogin = (req, res) => {
  const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
  const { idToken } = req.body;

  client
    .verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID })
    .then(response => {
      console.log("GOOGLE LOGIN RESPONSE", response);
      const { email_verified, name, email } = response.payload;
      if (email_verified) {
        User.findOne({ email }).exec((err, user) => {
          if (user) {
            const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
              expiresIn: "3h"
            });

            const { _id, email, name, role } = user;
            return res.json({
              token,
              user: { _id, email, name, role }
            });
          } else {
            let password = email + process.env.JWT_SECRET;
            user = new User({ name, email, password });
            user.save((err, data) => {
              if (err) {
                console.log("ERROR GOOGLE LOGIN ON USER SAVE", err);
                return res.status(500).json({
                  error: "User signup failed with google"
                });
              }
              // generate a token and send to client
              const token = jwt.sign(
                { _id: data._id },
                process.env.JWT_SECRET,
                {
                  expiresIn: "3h"
                }
              );

              const { _id, email, name, role } = data;
              return res.json({
                token,
                user: { _id, email, name, role }
              });
            });
          }
        });
      } else {
        return res.status(400).json({
          error: "Google login failed. Try again"
        });
      }
    });
};

exports.facebookLogin = (req, res) => {
  const { userID, accessToken } = req.body;

  const url = `https://graph.facebook.com/v2.11/${userID}/?fields=id,name,email&access_token=${accessToken}`;
  return fetch(url, {
    method: "GET"
  })
    .then(response => response.json())
    .then(response => {
      console.log("FACEBOOK RESPONSE", response);
      const { email, name } = response;
      User.findOne({ email }).exec((err, user) => {
        if (user) {
          const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
            expiresIn: "3h"
          });

          const { _id, email, name, role } = user;
          return res.json({
            token,
            user: { _id, email, name, role }
          });
        } else {
          let password = email + process.env.JWT_SECRET;
          user = new User({ name, email, password });
          user.save((err, data) => {
            if (err) {
              console.log("ERROR FACEBOOK LOGIN ON USER SAVE", err);
              return res.status(500).json({
                error: "User signup failed with facebook"
              });
            }
            // generate a token and send to client
            const token = jwt.sign({ _id: data._id }, process.env.JWT_SECRET, {
              expiresIn: "3h"
            });

            const { _id, email, name, role } = data;
            return res.json({
              token,
              user: { _id, email, name, role }
            });
          });
        }
      });
    })
    .catch(err => {
      console.log("FACEBOOK LOGIN FAILED ERROR", err);
      return res.status(400).json({
        error: "Facebook login failed. Try later"
      });
    });
};
