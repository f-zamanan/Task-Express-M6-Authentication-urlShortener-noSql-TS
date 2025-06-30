import { NextFunction, Request, Response } from "express";
import User from "../../models/User";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();
// generate the token
const generateToken = (id: string) => {
  const token = jwt.sign({ id }, process.env.JWT_SK as string, {
    expiresIn: "1h", // best practice is to add the expiration time in .env file, it's a security risk
  });

  return token;
};
// update sign up func
export const signup = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    // 1. extract user info from re.body > done
    const { username, password } = req.body;

    // 2. check if user alreadt exists or dupelicate?
    const userExists = await User.findOne({ username });
    if (userExists) {
      res.status(401).json("The User Already Exists");
    }
    // 3. hash the password
    const SALT = 10; // increases the complexity of the password (10-12)
    const enrcyptedPass = await bcrypt.hash(password, SALT);
    // 4. create the user
    const newUser = await User.create({ username, password: enrcyptedPass });
    // 5. generate token
    const generatedToken = generateToken(`${newUser._id}`); // id needs to be a string
    res.status(201).json(newUser);
  } catch (err) {
    next(err);
  }
};

export const signin = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
  } catch (err) {
    next(err);
  }
};

export const getUsers = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const users = await User.find().populate("urls");
    res.status(201).json(users);
  } catch (err) {
    next(err);
  }
};
