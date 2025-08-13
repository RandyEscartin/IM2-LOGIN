const express = require("express");
const router = express.Router();
const { register, login, logout } = require("../controllers/auth-controller");
const { verifyToken } = require("../middleware/auth-middleware");

router.post("/register", register);
router.post("/login", login);
router.post("/logout", logout);

// Protected route example
router.get("/profile", verifyToken, (req, res) => {
  res.json({
    message: "Profile accessed successfully",
    user: {
      id: req.user.userId,
      name: req.user.name,
      email: req.user.email
    }
  });
});

module.exports = router;
