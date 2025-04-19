import { comparePasswords, hashPassword } from "../utils/passwordHash.js";
import userModel from "../models/user.model.js";
import { generateAccessToken } from "../utils/generateAccessToken.js";
import { generateRefreshToken } from "../utils/generateRefreshToken.js";
import transporter from "../config/nodemailer.js";
import generateWelcomeEmail from "../email/generateWelcomeEmail.js";
import { welcomeEmail } from "../config/resend.js";
import { generateOTP } from "../utils/generateOTP.js";

export const registerController = async (req, res) => {
    const { name, email, password } = req.body;

    // Check if all fields are provided
    if (!name || !email || !password) {
        return res.status(400).json({
            success: false,
            message: "All fields are required."
        });
    }

    try {
        // Check if the user already exists
        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "User already exists."
            });
        }

        // Hash the password
        const hashedPassword = await hashPassword(password);

        // Create a new user
        const newUser = new userModel({
            name,
            email,
            password: hashedPassword
        });

        const savedUser = await newUser.save();

        // Generate access and refresh tokens
        const accessToken = generateAccessToken(savedUser);
        const refreshToken = generateRefreshToken(savedUser);

        // Cookie options
        const accessCookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: "None",
            maxAge: 15 * 60 * 1000 // 15 minutes
        };

        const refreshCookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: "None",
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        };

        // Set the cookies
        res.cookie("accessToken", accessToken, accessCookieOptions);
        res.cookie("refreshToken", refreshToken, refreshCookieOptions);

        /*
            Send Register email
        */
        // Send mail with nodemailer
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "Welcome to Auth Template",
            html: generateWelcomeEmail(name, `${process.env.CLIENT_URL}/login`)
        };
        await transporter.sendMail(mailOptions)

        // send email with resend
        // welcomeEmail(email, name, `${process.env.CLIENT_URL}/login`) 

        // Return the response with user data and tokens
        return res.status(201).json({
            message: "User registered successfully.",
            success: true,
            data: {
                user: savedUser,
                accessToken,
                refreshToken
            }
        });

    } catch (error) {
        // Error handling
        return res.status(500).json({
            success: false,
            message: error.message
        });
    }
};

export const loginController = async (req, res) => {

    try {
        const { email, password } = req.body

        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "All fields are required."
            });
        }

        const user = await userModel.findOne({ email })

        if (!user) {
            return res.status(400).json({
                message: "User not registered with this email!",
                success: false
            })
        }

        const isPasswordMatch = await comparePasswords(password, user.password);

        if (!isPasswordMatch) {
            return res.status(401).json({
                message: "Invalid credentials! Please check your email or password.",
                success: false,
            });
        }

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        // Cookie options
        const accessCookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: "None",
            maxAge: 15 * 60 * 1000 // 15 minutes
        };

        const refreshCookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: "None",
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        };

        // Set the cookies
        res.cookie("accessToken", accessToken, accessCookieOptions);
        res.cookie("refreshToken", refreshToken, refreshCookieOptions);

        return res.status(200).json({
            message: "Login successfully.",
            success: true,
            data: {
                user,
                accessToken,
                refreshToken
            }
        })

    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            success: false,
        })
    }
}

export const logoutController = async (req, res) => {
    try {
        res.clearCookie("accessToken", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "None"
        })
        res.clearCookie("refreshToken", {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "None"
        })

        return res.status(200).json({
            success: true,
            message: "Logged out successfully"
        });

    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            success: false,
        })
    }
}

export const sendVerificationOTP = async (req, res) => {
    try {
        const {userId} = req.body;

        const user = await userModel.findById(userId)
        
        if (!user) {
            return res.status(400).json({
                message: "No user found!",
                success: false
            })
        }

        if(user.isVerified) {
            return res.status(400).json({
                message: "Account is already verified!",
                success: false
            })
        }

        const otp = generateOTP()
        
        user.verifyOtp = otp
        user.verifyOtpExpiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes

        await user.save() //save
        
    } catch (error) {
        return res.status(500).json({
            message: error.message || error,
            success: false,
        })
    }
}