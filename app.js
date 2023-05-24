// Modules
const express = require('express');  
const bodyParser = require('body-parser');  // read information sent by users
const bcrypt = require('bcrypt');  // hash passwords
const jwt = require('jsonwebtoken');  
const mongoose = require('mongoose'); 
const session = require('express-session');  
const cors = require('cors');  // Front end connnection
const path = require('path');  
const User = require('./models');

// Express
const app = express();
const secretKey = 'your-secret-key';  // secret key used for signing tokens
app.use(express.json());
app.use(session({ secret: secretKey, resave: true, saveUninitialized: true }));

// View engine
// app.set('view engine', 'ejs'); // old, when testing backend with .ejs rendering

app.use(express.static(path.join(__dirname, 'client/build')));

// connect to a MongoDB
mongoose.connect('mongodb+srv://admin:pw@cluster0.6d8rfyu.mongodb.net/', { useNewUrlParser: true, useUnifiedTopology: true });

// CORS to allow front end to join from 3001
app.use(cors({ origin: ['http://localhost:3001', 'http://localhost:3002'] }));

// redirect to login
app.get('/', (req, res) => res.redirect('/login'));

// Login process
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username }); // find user in DB

  // If no user is found
  if (!user) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  // compare  password with database
  const result = await bcrypt.compare(password, user.password);
  console.log('Login request received');

  // If the passwords match, create an authentication token
  if (result) {
    const token = jwt.sign({ userId: user._id }, secretKey);

    user.token = token;
    await user.save();

    return res.json({ token }); // Return the token as a JSON response
  } else {
    // If the passwords don't match, return error
    return res.status(401).json({ error: 'Invalid username or password' });
  }
});

// Token check
function authenticateToken(req, res, next) {
  const token = req.query.token;

  // If no token is provided, return error
  if (!token) {
    return res.status(401).send('Unauthorized');
  }

  // Verify Token using secret key.
  jwt.verify(token, secretKey, (err, payload) => {
    if (err) {
      // If the token is invalid, return error
      return res.status(401).send('Unauthorized');
    }
    // If the token is valid, extract the user ID
    req.userId = payload.userId;
    next();
  });
}

//Token check for calculate
app.post('/calculate', authenticateToken, (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
});

// Signup Process
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  console.log('Signup request received:', username, password);

  // find user in DB
  const existingUser = await User.findOne({ username });

  // If the username already exists, return error
  if (existingUser) {
    return res.status(409).send('Username already exists');
  }

  // If the username doesn't exist, hash password and create user in the database
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({ username, password: hashedPassword });

  await newUser.save();

  return res.json({ message: 'Signup successful' });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'client/build', 'index.html')));

// Test fucntion, used to test communicationfrom back end to front end for debugging
// app.post('/test', (req, res) => {
//   console.log('Test route called');
//   res.status(200).json({ message: 'Test route successful' });
// });

app.listen(3000, () => console.log('Server started on port 3000'));
