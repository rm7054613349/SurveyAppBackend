const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const User = require('../models/User');
const { authMiddleware, roleMiddleware } = require('../middleware/authMiddleware');

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
ADMIN_ACCESS_EMAIL=["mishrahardic@gmail.com"] 
EMPLOYEE_ACCESS_EMAIL=["wwwritesh72660@gmail.com"]

// Signup
router.post('/signup', async (req, res) => {
  const { email, password, role } = req.body;
  try {
    if (!email || !password || !role) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    if (!['admin', 'employee'].includes(role)) {
      return res.status(400).json({ message: 'Invalid role' });
    }
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }
    // Check role from environment variables
    const allowedAdmins = JSON.parse(ADMIN_ACCESS_EMAIL || '[]');
    const allowedEmployees = JSON.parse(EMPLOYEE_ACCESS_EMAIL || '[]');
    if (role === 'admin' && !allowedAdmins.includes(email)) {
      return res.status(403).json({ message: 'Not authorized to sign up as admin' });
    }
    if (role === 'employee' && !allowedEmployees.includes(email)) {
      return res.status(403).json({ message: 'Not authorized to sign up as employee' });
    }
    user = new User({ email, password, role });
    await user.save();
    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    res.status(201).json({ token, id: user._id, role: user.role, email: user.email });
  } catch (err) {
    console.error('Signup error:', err.message);
    res.status(500).json({ message: err.message });
  }
});



// Login
router.post('/login', async (req, res) => {
  const { email, password, role } = req.body;
  try {
    if (!email || !password || !role) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    const user = await User.findOne({ email });
    if (!user || user.role !== role) {
      return res.status(400).json({ message: 'User not authorized' });
    }
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    // Check role from environment variables
    const allowedAdmins = JSON.parse(process.env.ADMIN_ACCESS_EMAIL || '[]');
    const allowedEmployees = JSON.parse(process.env.EMPLOYEE_ACCESS_EMAIL || '[]');
    const emailRoleMapping = [
      ...allowedAdmins.map(email => ({ email, role: 'admin' })),
      ...allowedEmployees.map(email => ({ email, role: 'employee' })),
    ];
    const userMapping = emailRoleMapping.find(mapping => mapping.email === email);
    if (!userMapping || userMapping.role !== role) {
      return res.status(403).json({ message: 'User not authorized for this role' });
    }
    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    res.json({ token, id: user._id, role: user.role, email: user.email });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// Google Login
router.post('/google-login', async (req, res) => {
  const { credential } = req.body;
  try {
    if (!credential) {
      return res.status(400).json({ message: 'Google credential is required' });
    }
    const ticket = await client.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const email = payload['email'];
    let user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'User not found ' });
    }
    // Check role from environment variables
    const allowedAdmins = JSON.parse(process.env.ADMIN_ACCESS_EMAIL || '[]');
    const allowedEmployees = JSON.parse(process.env.EMPLOYEE_ACCESS_EMAIL || '[]');
    const emailRoleMapping = [
      ...allowedAdmins.map(email => ({ email, role: 'admin' })),
      ...allowedEmployees.map(email => ({ email, role: 'employee' })),
    ];
    const userMapping = emailRoleMapping.find(mapping => mapping.email === email);
    if (!userMapping || userMapping.role !== user.role) {
      return res.status(403).json({ message: 'User not authorized for this role' });
    }
    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    res.json({ token, id: user._id, role: user.role, email: user.email });
  } catch (err) {
    console.error('Google login error:', err.message);
    res.status(500).json({ message: err.message || 'Google login failed' });
  }
});

// Get all users (Admin only)
router.get('/users', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (err) {
    console.error('Get users error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// Change password
router.post('/change-password', authMiddleware, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  try {
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Current and new password are required' });
    }
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    const isMatch = await user.matchPassword(currentPassword);
    if (!isMatch) {
      return res.status(400).json({ message: 'Current password is incorrect' });
    }
    if (newPassword.length < 6) {
      return res.status(400).json({ message: 'New password must be at least 6 characters long' });
    }
    user.password = newPassword;
    await user.save();
    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error('Change password error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// Get user profile
router.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({
      id: user._id,
      email: user.email,
      role: user.role,
      badges: user.badges || [],
    });
  } catch (err) {
    console.error('Get user profile error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;