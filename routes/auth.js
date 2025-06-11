const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const passport = require('./passport');
const User = require('../models/User');
const { authMiddleware, roleMiddleware } = require('../middleware/authMiddleware');

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Signup (unchanged)
router.post('/signup', async (req, res) => {
  const { email, password, role } = req.body;
  console.log('Signup request:', { email, role, timestamp: new Date().toISOString() });
  try {
    if (!email || !password || !role) {
      return res.status(400).json({ message: 'All fields are required' });
    }
    if (!['admin', 'employee', 'NewHire'].includes(role)) {
      console.log('Invalid role detected:', role);
      return res.status(400).json({ message: 'Invalid role' });
    }
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: 'User already exists' });
    }
    let allowedAdmins = [];
    let allowedEmployees = [];
    let allowedNewHires = [];
    try {
      allowedAdmins = JSON.parse(process.env.ADMIN_ACCESS_EMAIL || '[]');
      allowedEmployees = JSON.parse(process.env.EMPLOYEE_ACCESS_EMAIL || '[]');
      allowedNewHires = JSON.parse(process.env.NEW_HIRE_ACCESS_EMAIL || '[]');
      console.log('Allowed emails:', { allowedNewHires });
    } catch (e) {
      console.error('Error parsing env emails:', e.message);
      return res.status(500).json({ message: 'Server configuration error' });
    }
    if (role === 'admin' && !allowedAdmins.includes(email)) {
      return res.status(403).json({ message: 'Not authorized to sign up as admin' });
    }
    if (role === 'employee' && !allowedEmployees.includes(email)) {
      return res.status(403).json({ message: 'Not authorized to sign up as employee' });
    }
    if (role === 'NewHire' && !allowedNewHires.includes(email)) {
      return res.status(403).json({ message: 'Not authorized to sign up as NewHire' });
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
    console.error('Signup error:', { message: err.message, timestamp: new Date().toISOString() });
    res.status(500).json({ message: err.message });
  }
});

// Login (modified)
router.post('/login', async (req, res) => {
  const { email, password, role } = req.body;
  console.log('Login request:', { email, role, timestamp: new Date().toISOString() });
  try {
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    let allowedAdmins = [];
    let allowedEmployees = [];
    let allowedNewHires = [];
    try {
      allowedAdmins = JSON.parse(process.env.ADMIN_ACCESS_EMAIL || '[]');
      allowedEmployees = JSON.parse(process.env.EMPLOYEE_ACCESS_EMAIL || '[]');
      allowedNewHires = JSON.parse(process.env.NEW_HIRE_ACCESS_EMAIL || '[]');
    } catch (e) {
      console.error('Error parsing env emails:', e.message);
      return res.status(500).json({ message: 'Server configuration error' });
    }
    const emailRoleMapping = [
      ...allowedAdmins.map(email => ({ email, role: 'admin' })),
      ...allowedEmployees.map(email => ({ email, role: 'employee' })),
      ...allowedNewHires.map(email => ({ email, role: 'NewHire' })),
    ];
    const userMapping = emailRoleMapping.find(mapping => mapping.email === email);
    if (!userMapping) {
      return res.status(403).json({ message: 'User not authorized' });
    }
    const inferredRole = role || userMapping.role;
    if (userMapping.role !== inferredRole) {
      return res.status(403).json({ message: 'User not authorized for this role' });
    }
    const user = await User.findOne({ email });
    if (!user || user.role !== inferredRole) {
      return res.status(400).json({ message: 'User not authorized' });
    }
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }
    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    res.json({ token, id: user._id, role: user.role, email: user.email });
  } catch (err) {
    console.error('Login error:', { message: err.message, timestamp: new Date().toISOString() });
    res.status(500).json({ message: err.message });
  }
});

// Google Login (unchanged)
router.post('/google-login', async (req, res) => {
  const { credential } = req.body;
  console.log('Google login request:', { timestamp: new Date().toISOString() });
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
      return res.status(400).json({ message: 'User not found' });
    }
    let allowedAdmins = [];
    let allowedEmployees = [];
    let allowedNewHires = [];
    try {
      allowedAdmins = JSON.parse(process.env.ADMIN_ACCESS_EMAIL || '[]');
      allowedEmployees = JSON.parse(process.env.EMPLOYEE_ACCESS_EMAIL || '[]');
      allowedNewHires = JSON.parse(process.env.NEW_HIRE_ACCESS_EMAIL || '[]');
    } catch (e) {
      console.error('Error parsing env emails:', e.message);
      return res.status(500).json({ message: 'Server configuration error' });
    }
    const emailRoleMapping = [
      ...allowedAdmins.map(email => ({ email, role: 'admin' })),
      ...allowedEmployees.map(email => ({ email, role: 'employee' })),
      ...allowedNewHires.map(email => ({ email, role: 'NewHire' })),
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
    console.error('Google login error:', { message: err.message, timestamp: new Date().toISOString() });
    res.status(500).json({ message: err.message || 'Google login failed' });
  }
});

// GreytHR SSO (unchanged)
router.get('/greythr-sso', passport.authenticate('saml', {
  failureRedirect: '/',
  failureFlash: true,
}));

router.post('/greythr-sso/callback', passport.authenticate('saml', {
  failureRedirect: '/',
  failureFlash: true,
}), async (req, res) => {
  try {
    const { email, role } = req.user;
    console.log('GreytHR SSO callback:', { email, role, timestamp: new Date().toISOString() });
    let allowedAdmins = [];
    let allowedEmployees = [];
    let allowedNewHires = [];
    try {
      allowedAdmins = JSON.parse(process.env.ADMIN_ACCESS_EMAIL || '[]');
      allowedEmployees = JSON.parse(process.env.EMPLOYEE_ACCESS_EMAIL || '[]');
      allowedNewHires = JSON.parse(process.env.NEW_HIRE_ACCESS_EMAIL || '[]');
    } catch (e) {
      console.error('Error parsing env emails:', e.message);
      return res.status(500).json({ message: 'Server configuration error' });
    }
    const emailRoleMapping = [
      ...allowedAdmins.map(email => ({ email, role: 'admin' })),
      ...allowedEmployees.map(email => ({ email, role: 'employee' })),
      ...allowedNewHires.map(email => ({ email, role: 'NewHire' })),
    ];
    const userMapping = emailRoleMapping.find(mapping => mapping.email === email);
    if (!userMapping) {
      return res.status(403).json({ message: 'Email not authorized' });
    }
    let user = await User.findOne({ email });
    if (!user) {
      user = new User({ email, role: userMapping.role });
      await user.save();
    } else if (user.role !== userMapping.role) {
      return res.status(403).json({ message: 'User not authorized for this role' });
    }
    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );
    res.redirect(`${process.env.APP_BASE_URL}/sso-callback?token=${encodeURIComponent(token)}&role=${user.role}&email=${encodeURIComponent(user.email)}&id=${user._id}`);
  } catch (err) {
    console.error('GreytHR SSO error:', { message: err.message, timestamp: new Date().toISOString() });
    res.redirect(`${process.env.APP_BASE_URL}?error=${encodeURIComponent(err.message || 'GreytHR SSO failed')}`);
  }
});

// Get all users (admin only, unchanged)
router.get('/users', authMiddleware, roleMiddleware('admin'), async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json(users);
  } catch (err) {
    console.error('Get users error:', { message: err.message, timestamp: new Date().toISOString() });
    res.status(500).json({ message: err.message });
  }
});

// Change password (unchanged)
router.post('/change-password', authMiddleware, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  try {
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: 'Current and new passwords are required' });
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
    console.error('Change password error:', { message: err.message, timestamp: new Date().toISOString() });
    res.status(500).json({ message: err.message });
  }
});

// Get user profile (unchanged)
router.get('/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password');
    res.json({
      id: user._id,
      email: user.email,
      role: user.role,
      badges: user.badges || [],
    });
  } catch (err) {
    console.error('Get user profile error:', { message: err.message, timestamp: new Date().toISOString() });
    res.status(500).json({ message: err.message });
  }
});

// Debug endpoint (unchanged)
router.get('/version', (req, res) => {
  res.json({ version: '1.0.0', rolesSupported: ['admin', 'employee', 'NewHire'] });
});

module.exports = router;