const express = require("express");
const app = express();

// CORS
const cors = require("cors");
app.use(cors());

// Prevent NOSQLI

const expressMongoSanitize = require("@exortek/express-mongo-sanitize");

app.use(expressMongoSanitize());

// Rate limit 

const rateLimit = require("express-rate-limit");
const limiter = rateLimit({
  windowMs: 2 * 60 * 1000, // 1 minutes
  max: 50, // Limit each IP to 50 requests per `window` (here, per 2 minutes)
});
app.use(limiter);

require('dotenv').config(); // load .env variables
const API_KEY =process.env.VT_API_KEY;
const mongoose = require("mongoose");
mongoose.connect(process.env.DB_LINK)
  .then(() => console.log("DB connected successfully"))
  .catch(err => console.error("DB connection error:", err));



const checkRoutes = require("./routes/Check_routes");
const authRoutes = require("./routes/auth_route");



app.use(express.static('public'));
app.use(express.json());

app.use(checkRoutes);
app.use(authRoutes)

 

app.get('/',(req,res,next) => {
    res.json({msg:"working well"});
});

app.use( (req, res, next) => {
    res.status(404).json({msg: '404 not found'});
});

const PORT = 443;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
