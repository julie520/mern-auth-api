const router = require("express").Router();

// import controller
const { authMiddleware, adminMiddleware } = require("../controllers/auth");
const { read, update } = require("../controllers/user");

router.get("/user/:id", authMiddleware, read);
router.put("/user/update", authMiddleware, update);
router.put("/admin/update/:id", authMiddleware, adminMiddleware, update);
module.exports = router;
