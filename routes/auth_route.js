const authController = require("../controllers/auth_controller");
const express = require("express");
const router = express.Router();
const passport = require("passport");

require("../Services/passportConfig");

router.route("/sign-up").post(authController.singUP);
router.route("/login").post(authController.login);
router.post("/forgotPassword", authController.forgotPassword);
router.post("/resetPassword/:token", authController.resetPassword);

// google auth

router.route("/google").get(
  passport.authenticate("google", {
    scope: [
      "https://www.googleapis.com/auth/userinfo.profile",
      "https://www.googleapis.com/auth/userinfo.email"
    ]
  })
);

router.get("/google/callback", 
  (req, res, next) => {
    console.log('=== CALLBACK HIT ===');
    console.log('Query params:', req.query);
    console.log('Full URL:', req.url);
    next();
  },
  passport.authenticate("google", { failureRedirect: "/", session: false }),
  authController.logWithGoogle
);

module.exports = router;
