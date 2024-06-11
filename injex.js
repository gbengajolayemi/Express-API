require('dotenv').config(); // Load .env file

const cors = require('cors');
const mongoose = require('mongoose');
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto'); // Import crypto module for generating secret key
const bcrypt = require('bcrypt'); // Import bcrypt for password hashing
const rateLimit = require('express-rate-limit'); // Import rate-limiting middleware
const morgan = require('morgan');
const { body, validationResult } = require('express-validator');
const mongoSanitize = require('express-mongo-sanitize');



// Initialization
const app = express();
const port = process.env.PORT || 4000;

// Enable trust proxy
app.set('trust proxy', true);

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan('combined'));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!' });
});

// Request validation middleware
app.use((req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  next();
});

// Input sanitization middleware
app.use(mongoSanitize());

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// MongoDB connection
const MONGODB_URI = process.env.MONGODB_URI;
mongoose.connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB Atlas connection error:'));
db.once('open', () => console.log('Connected to MongoDB Atlas'));

// User schema and model
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  username: String,
  password: String,
  failedLoginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
});

const User = mongoose.model('User', userSchema);

// Middleware function to verify JWT token
function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'Access denied. No token provided.' });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Invalid token.' });
    req.user = decoded;
    next();
  });
}

// Registration route
app.post("/register", [
  body('firstName').notEmpty().withMessage('First name is required'),
  body('lastName').notEmpty().withMessage('Last name is required'),
  body('username').notEmpty().withMessage('Username is required'),
  body('password').notEmpty().withMessage('Password is required'),
], async (req, res) => {
  const { firstName, lastName, username, password } = req.body;

  // Check if username already exists
  const existingUser = await User.findOne({ username: username });
  if (existingUser) {
    return res.status(400).json({ message: 'Username already exists.' });
  }

  // Hash the password before storing it
  const hashedPassword = await bcrypt.hash(password, 10);

  // Create a new user
  const user = new User({
    firstName: firstName,
    lastName: lastName,
    username: username,
    password: hashedPassword,
  });

  try {
    const newUser = await user.save();
    res.status(201).json(newUser);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Login route to generate token
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  // Find user by username
  const user = await User.findOne({ username: username });
  if (!user) {
    return res.status(401).json({ message: 'Invalid username or password.' });
  }

  // Check if the account is locked
  if (user.lockUntil && user.lockUntil > Date.now()) {
    // Account is locked
    const remainingTime = Math.ceil((user.lockUntil - Date.now()) / 1000); // Remaining lock time in seconds
    return res.status(403).json({ message: 'Account is locked.', remainingTime: remainingTime });
  }

  // Check password
  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    user.failedLoginAttempts += 1;
    if (user.failedLoginAttempts >= 3) {
      user.lockUntil = Date.now() + (15 * 60 * 1000); // Lock for 15 minutes
      user.failedLoginAttempts = 0;
    }
    await user.save();
    return res.status(401).json({ message: 'Invalid username or password.' });
  }

  // Reset failed login attempts on successful login
  user.failedLoginAttempts = 0;
  user.lockUntil = undefined;
  await user.save();

  // Generate token
  const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});

// Get all users
app.get("/user", verifyToken, async (req, res) => {
  try {
    const users = await User.find();
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Add a new user
app.post("/user", verifyToken, async (req, res) => {
  const { firstName, lastName } = req.body;

  const user = new User({
    firstName: firstName,
    lastName: lastName,
  });

  try {
    const newUser = await user.save();
    res.status(201).json(newUser);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Get a user by ID
app.get("/user/:id", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (user == null) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Update a user by ID
app.put("/user/:id", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (user == null) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (req.body.firstName != null) {
      user.firstName = req.body.firstName;
    }
    if (req.body.lastName != null) {
      user.lastName = req.body.lastName;
    }

    const updatedUser = await user.save();
    res.json(updatedUser);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

  
  // Delete a user by ID
  app.delete("/user/:id", verifyToken, async (req, res) => {
    try {
      const user = await User.findById(req.params.id);
      if (user == null) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      await user.remove();
      res.json({ message: 'User deleted' });
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  });
  
  // Listen
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
  
