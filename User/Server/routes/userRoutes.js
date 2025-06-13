const express = require('express');
const router = express.Router();
const {
  registerUser,
  verifyOTP,
  loginUser,
  followUser,
  unfollowUser,
  getUserProfile
} = require('../controllers/userController');

router.post('/register', registerUser);
router.post('/verify-otp', verifyOTP);
router.post('/login', loginUser);
router.post('/follow/:id', followUser);
router.post('/unfollow/:id', unfollowUser);
router.get('/profile/:id', getUserProfile);

module.exports = router;
