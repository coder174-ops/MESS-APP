const User =require('../Models/User')
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const fs = require('fs');
const path = require('path');

require('dotenv').config();
const JWT_SECRET = process.env.JWT_SECRET;

console.log("Loaded AppEmail:", process.env.AppEmail);
console.log("Loaded AppPassword:", process.env.AppPassword);

// Load email template
const loadTemplate = (filePath) => {
  return fs.readFileSync(filePath, { encoding: 'utf-8' });
};

// Nodemailer transporter configuration
const transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 587,
  secure: false,
  auth: {
    user: process.env.AppEmail,
    pass: process.env.AppPassword,

  },
  tls: {
    rejectUnauthorized: false,
  },
  connectionTimeout: 60000,
});

const sendOTP = async (email, otp) => {
  try {
    const templatePath = path.join(__dirname, "../emailTemplate.html");
    const htmlContent = loadTemplate(templatePath).replace('{{OTP}}', otp);

    const mailOptions = {
      from: process.env.AppEmail,
      to: email,
      subject: 'Your OTP for Registration',
      html: htmlContent,
    };

    await transporter.sendMail(mailOptions);
    console.log('Email sent successfully');
  } catch (error) {
    const now = Date.now();
    await User.deleteMany({ isVerified: false, otpExpiresAt: { $lt: now } });
    console.error('Error sending email:', error);
    throw new Error('Email sending failed');
  }
};

// Generate OTP 
const generateOTP = () => crypto.randomBytes(3).toString('hex');

// User Registration
exports.registerUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ msg: 'User already exists' });
    }

    const username = `@${email.split('@')[0]}`;
    const otp = generateOTP();
    const otpExpiresAt = Date.now() + 10 * 60 * 1000; // OTP expires in 10 minutes

    // Create new user with hashed password
    if (password) {
      const salt = await bcrypt.genSalt();
      const hashedPassword = await bcrypt.hash(password, salt);

      user = new User({
        email,
        username,
        otp,
        otpExpiresAt,
        password: hashedPassword
      });

      await user.save(); // Save user to generate user.id
      
      // Create JWT token
      const payload = {
        user: { _id: user._id } 
      };
      await sendOTP(email, otp);
      jwt.sign(payload, JWT_SECRET, (err, token) => {
        if (err) throw err;
        user.token = token;
        user.save().then(() => {
          console.log("Token saved successfully");
        });
        res.status(201).json({
          message: 'OTP sent to your email. Please verify to complete registration.',
          token
        });
      });
    } else {
      return res.status(400).json({ msg: 'Password and Confirm password should be the same' });
    }
  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
};

// Verify OTP
exports.verifyOTP = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    if (user.otp === otp && user.otpExpiresAt > Date.now()) {
      user.isVerified = true;
      user.otp = undefined;
      user.otpExpiresAt = undefined;
      await user.save();

      return res.status(200).json({ message: 'User verified successfully' });
    } else {
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

// User Login
exports.loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user || !user.isVerified) {
      return res.status(400).json({ error: 'Invalid email or user not verified' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    // Generate a JWT token for the user
    const token = jwt.sign({ userId: user._id }, JWT_SECRET);

    res.json({ token, user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

// Follow a user
exports.followUser = async (req, res) => {
  const userId = req.user.id;
  const targetUserId = req.params.id;

  try {
    const user = await User.findById(userId);
    const targetUser = await User.findById(targetUserId);

    if (!targetUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.following.includes(targetUserId)) {
      return res.status(400).json({ error: 'Already following this user' });
    }

    user.following.push(targetUserId);
    targetUser.followers.push(userId);

    await user.save();
    await targetUser.save();

    res.status(200).json({ message: 'User followed successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

// Unfollow a user
exports.unfollowUser = async (req, res) => {
  const userId = req.user.id;
  const targetUserId = req.params.id;

  try {
    const user = await User.findById(userId);
    const targetUser = await User.findById(targetUserId);

    if (!targetUser) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!user.following.includes(targetUserId)) {
      return res.status(400).json({ error: 'You are not following this user' });
    }

    user.following = user.following.filter(followingId => followingId.toString() !== targetUserId.toString());
    targetUser.followers = targetUser.followers.filter(followerId => followerId.toString() !== userId.toString());

    await user.save();
    await targetUser.save();

    res.status(200).json({ message: 'User unfollowed successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};

// Get user profile
exports.getUserProfile = async (req, res) => {
  try {
    const user = await User.findById(req.params.id).populate('songsPosted').populate('songsLiked');

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
};
