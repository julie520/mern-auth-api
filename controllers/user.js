const User = require("../models/user");

exports.read = (req, res) => {
  const userId = req.params.id;
  User.findById(userId, { hashedPassword: 0, salt: 0 }).exec((err, user) => {
    if (err || !user) {
      return res.status(404).json({
        error: "User not found"
      });
    }
    res.json(user);
  });
};

exports.update = (req, res) => {
  // console.log("UDPDATE USER - req.user", req.user, "UDATE DATA", req.body);
  let userId = req.user._id;
  const { name, password } = req.body;

  if (req.profile && req.profile.role === "admin" && req.params.id)
    userId = req.params.id;

  User.findById(userId, (err, user) => {
    if (err || !user) {
      return res.status(404).json({
        error: "User not found"
      });
    }
    if (!name) {
      return res.status(400).json({
        error: "Name is required"
      });
    }
    user.name = name;
    if (password) {
      if (password.length < 6) {
        return res.status(400).json({
          error: "Password should be min 6 characters long"
        });
      }
      user.password = password;
    }
    user.save((err, updatedUser) => {
      if (err) {
        console.log("USER UPDATE ERROR", err);
        return res.status(500).json({
          error: "User update failed"
        });
      }

      delete updatedUser.hashedPassword;
      delete updatedUser.salt;

      res.json(updatedUser);
    });
  });
};
