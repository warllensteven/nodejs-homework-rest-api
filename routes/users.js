const express = require("express");
const router = express.Router();
const User = require("../models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const generateJWT = (userId) => {
  const secretKey = process.env.JWT_SECRET_KEY || "your_secret_key_here";
  const token = jwt.sign({ userId }, secretKey, { expiresIn: "1h" });
  return token;
};

const hashPassword = async (password) => {
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  return hashedPassword;
};

const comparePassword = async (password, hashedPassword) => {
  const isValid = await bcrypt.compare(password, hashedPassword);
  return isValid;
};

router.post("/signup", async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Email already in use" });
    }

    const hashedPassword = await hashPassword(password);

    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    const token = generateJWT(newUser._id);

    res.status(201).json({ user: { email: newUser.email }, token });
  } catch (error) {
    next(error);
  }
});

router.post("/login", async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Email or password is wrong" });
    }

    const isValidPassword = await comparePassword(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ message: "Email or password is wrong" });
    }

    const token = generateJWT(user._id);

    res.status(200).json({ token, user: { email: user.email } });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
