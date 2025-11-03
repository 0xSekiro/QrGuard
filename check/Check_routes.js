import express from "express";
const router = express.Router();
import * as CHU from "./Check_Controller.js";

router.post('/check', CHU.check_url);

export default router;
