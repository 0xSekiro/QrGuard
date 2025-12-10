const express = require("express");
const router = express.Router();
const authController = require("../controllers/auth_controller")

const CHU = require("../controllers/Check_Controller"); 

router.post('/check', authController.checkAuthorization,CHU.check_url);

module.exports = router; 

