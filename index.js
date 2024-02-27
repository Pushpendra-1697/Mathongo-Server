// Import required libraries
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const { config } = require('dotenv');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
require('dotenv').config();

// Initialize Express app
const app = express();

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/kanban', { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;

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
      // Create new user if not found
      user = await User.create({
        googleId: profile.id,
        name: profile.displayName,
        email: profile.emails[0].value,
        avatar: 'URL to randomly generated avatar'
      });
    }
    return done(null, user);
  }
));

// Routes
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

  jwt.verify(token, '', (err, decoded) => {
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

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
