const User = require("../models/auth-model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const register = async (req, res) => {
  const { name, email, password } = req.body;

  //   validation
  let errors = [];
  if (!name) errors.push({ field: name, message: "name is required" });
  if (!email) errors.push({ field: email, message: "email is required" });
  if (!password)
    errors.push({ field: password, message: "password is required" });

  if (errors.length > 0) return res.status(404).json(errors);

  try {
    const emailExists = await User.ifEmailExists(email);
    if (emailExists)
      return res.status(400).json({ message: "Email is already registered." });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    try {
      await User.createUser(name, email, hashedPassword);
    } catch (error) {
      console.log(error);
    }

    res.status(201).json({
      message: "User has been created successfully.",
    });
  } catch (error) {
    console.log(error);
  }
};

const login = async (req, res) => {
  const { email, password } = req.body;

  // validation
  let errors = [];
  if (!email) errors.push({ field: "email", message: "email is required" });
  if (!password) errors.push({ field: "password", message: "password is required" });

  if (errors.length > 0) return res.status(400).json(errors);

  try {
    // Check if user exists
    const user = await User.ifEmailExists(email);
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid email or password." });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user.id, 
        email: user.email,
        name: user.name 
      },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: "24h" }
    );

    // Set token in HTTP-only cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production", // true in production
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    });

    res.status(200).json({
      message: "Login successful.",
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error." });
  }
};

const logout = async (req, res) => {
  try {
    // Clear the token cookie
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict"
    });

    res.status(200).json({ message: "Logout successful." });
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal server error." });
  }
};

module.exports = { register, login, logout };
