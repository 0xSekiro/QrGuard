import express from "express"
const app = express();
import checkRoutes from './check/Check_routes.js';



app.use(express.static('public'));
app.use(express.json());

app.use(checkRoutes);
 

app.get('/',(req,res,next) => {

    res.json({msg:"working well"});
});

app.use( (req, res, next) => {
    res.status(404).json({msg: '404 not found'});
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
