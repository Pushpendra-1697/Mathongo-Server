// Import required libraries
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
require('dotenv').config();
const PORT = process.env.PORT || 3000; //defined port 8000 (default 3000) excluding 27017 (reserved port by Mongod);
const { connection } = require('./Configs/Config');
const axios = require('axios');
const rateLimit = require('express-rate-limit');

// Create a limiter with a maximum of 500 requests per minute
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 500, // limit each IP to 500 requests per windowMs
  message: 'Too many requests, please try again later.'
});

// Initialize Express app
const app = express();

// Define schemas
const UserSchema = new mongoose.Schema({
  googleId: String,
  name: String,
  email: String,
  avatar: String,
  recentlyVisitedBoards: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Board' }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const BoardSchema = new mongoose.Schema({
  name: String,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const TaskSchema = new mongoose.Schema({
  board: { type: mongoose.Schema.Types.ObjectId, ref: 'Board' },
  title: String,
  description: String,
  category: { type: String, enum: ['Unassigned', 'In Development', 'Pending Review', 'Done'] },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  deadline: Date,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', UserSchema);
const Board = mongoose.model('Board', BoardSchema);
const Task = mongoose.model('Task', TaskSchema);

// Apply the rate limiter to all requests
app.use(limiter);
// Passport middleware setup
app.use(passport.initialize());

// Passport Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: 'your-client-id',
  clientSecret: 'your-client-secret',
  callbackURL: '/auth/google/callback'
},
  async (accessToken, refreshToken, profile, done) => {
    // Check if user already exists in database
    let user = await User.findOne({ googleId: profile.id });
    if (!user) {
      // Generate avatar using external API (e.g., DiceBear)
      const avatarResponse = await axios.get('https://avatars.dicebear.com/api/micah/:seed.svg', {
        params: {
          seed: profile.id // Use Google profile id as seed for avatar
        }
      });
      const avatarURL = avatarResponse.data;

      // Create new user with generated avatar
      user = await User.create({
        googleId: profile.id,
        name: profile.displayName,
        email: profile.emails[0].value,
        avatar: avatarURL
      });
    }
    return done(null, user);
  }
));

// Routes
app.get('/', (req, res) => {
  res.send({ msg: 'Welcome to the kanban Application!!!! 😊✌️' })
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => {
    // Successful authentication, redirect to dashboard
    const token = jwt.sign({ userId: req.user._id }, process.env.secretKey);
    res.redirect(`/dashboard?token=${token}`);
  });

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.query.token || req.headers.authorization;
  if (!token) return res.status(401).json({ message: 'Unauthorized' });

  jwt.verify(token, process.env.secretKey, (err, decoded) => {
    if (err) return res.status(401).json({ message: 'Unauthorized' });
    req.userId = decoded.userId;
    next();
  });
};

// Example protected route
app.get('/api/user', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) throw new Error('User not found');
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

//server code for start or live my server at defined port;
app.listen(PORT, async () => {
  try {
    await connection;
    console.log("connected to DB");
  } catch (e) {
    console.log({ message: e.message });
  }
  console.log(`Server is running at port ${PORT}`);
});
