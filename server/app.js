const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
require("dotenv").config();
const secret = process.env.SECRET;
// Create Express app
const app = express();
app.use(express.json())
// Set up MongoDB connection

const DB = process.env.DATABASE;
mongoose.connect(DB, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => console.log('Connected to MongoDB'))
  .catch(error => console.error('MongoDB connection error:', error));

// Define user schema
const UserSchema = new mongoose.Schema({
    email: String,
    username: String,
  password: String
});

const User = mongoose.model('User', UserSchema);

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(401).json({ message: 'No token provided.' });
  }

  jwt.verify(token,secret, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Failed to authenticate token.' });
    }
    req.userId = decoded.id;
    next();
  });
};

// Register user
app.post('/register',async (req,res)=>{
    const {email,username,password} = req.body
    try {
        const UserExist = await User.findOne({email : email});
   
        if(UserExist){
         return res.status(400).json({message:"user already exists"});
        }
        const hashedpassword = bcrypt.hashSync(password,10)

        const user = new User({username,email,password:hashedpassword});
        
        await user.save();
   
        res.status(201).json({message:"registration successully done"});
   
   
     } catch (error) {
        console.log(error);
     }

})

// Login user and generate JWT token
app.post('/login',async (req, res) => {
  const {email, password } = req.body;
  const user = await User.findOne({email})
  if(!user)
  {
    return res.status(401).json({ message: 'Invalid email or password.' });
  }
    bcrypt.compare(password, user.password, (err, result) => {
      if (err || !result) {
        return res.status(401).json({ message: 'Invalid email or password.' });
      }
      const token = jwt.sign({ id: user._id },secret, { expiresIn: '1h' });
      res.status(200).json({ token });
    });
  });


// Protected route
app.get('/protected', verifyToken, (req, res) => {
  res.json({ message: 'Protected route accessed.' });
});


app.get('/users',verifyToken,async (req,res)=>{
    try {
        const users = await User.find()
        res.status(200).json(users)
    } catch (error) {
       res.status(400).json({message:error}) 
    }
})
// Logout user (optional, as JWT tokens are stateless)

// Start the server
app.listen(3000, () => {
  console.log('Server is listening on port 3000');
});
