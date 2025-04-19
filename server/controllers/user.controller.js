import { comparePasswords, hashPassword } from "../utils/passwordHash.js";
import userModel from "../models/user.model.js";
import { generateAccessToken } from "../utils/generateAccessToken.js";
import { generateRefreshToken } from "../utils/generateRefreshToken.js";
import transporter from "../config/nodemailer.js";
import generateVerificationToken from "../utils/generateVerificationToken.js";

export const registerController = async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({
            success: false,
            message: "All fields are required."
        });
    }

    try {
        const existingUser = await userModel.findOne({ email });
        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "User already exists."
            });
        }

        const hashedPassword = await hashPassword(password);

        // Generate a unique verification token
        const verificationToken = generateVerificationToken();

        const newUser = new userModel({
            name,
            email,
            password: hashedPassword,
            isVerified: false,
            verificationToken, // Store the token
            verificationTokenExpiration: Date.now() + 3600000 // Token expires in 1 hour
        });
        console.log("About to save user:", newUser);

        const savedUser = await newUser.save();
        console.log("Saved user:", savedUser);

        // Send the verification link with the token
        const verifyLink = `${process.env.CLIENT_URL}/verify-user?token=${verificationToken}`;

        // Send the verification email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "Verify your email - Auth Template",
            html: `
                <h1>Hi ${name},</h1>
                <p>Please verify your email by clicking the button below:</p>
                <a href="${verifyLink}" style="padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Verify Email</a>
            `
        };

        await transporter.sendMail(mailOptions);

        // Generate access and refresh tokens right after registration
        const accessToken = generateAccessToken(savedUser);
        const refreshToken = generateRefreshToken(savedUser);

        const accessCookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: "None",
            maxAge: 15 * 60 * 1000, // 15 minutes
        };

        const refreshCookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: "None",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        };

        res.cookie("accessToken", accessToken, accessCookieOptions);
        res.cookie("refreshToken", refreshToken, refreshCookieOptions);

        return res.status(201).json({
            message: "User registered. Please check your email to verify your account.",
            success: true
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: error.message
        });
    }
};

export const verifyUserController = async (req, res) => {
    const { token } = req.params; 
    
    if (!token) {
        return res.status(400).json({
            success: false,
            message: "Verification token is missing."
        });
    }

    try {
        // Find the user by the verification token
        const user = await userModel.findOne({ verificationToken: token });
        
        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Invalid tokens."
            });
        }

        if(user.isVerified) {
            return res.status(400).json({
                success: false,
                message: "User is already verified."
            })
        }

        // Check if the token has expired
        if (user.verificationTokenExpiration < Date.now()) {
            return res.status(400).json({
                success: false,
                message: "Verification token has expired."
            });
        }

        // Mark the user as verified
        user.isVerified = true;
        user.verificationToken = ""; 
        user.verificationTokenExpiration = "";
        await user.save();

        // Generate new tokens after verification (for refreshed authentication)
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

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

        res.cookie("accessToken", accessToken, accessCookieOptions);
        res.cookie("refreshToken", refreshToken, refreshCookieOptions);

        return res.status(200).json({
            success: true,
            message: "Account verified successfully."
        })

        // Option 1: Redirect to frontend (Home page after successful verification)
        // res.redirect(`${process.env.CLIENT_URL}/`);

    } catch (error) {
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

export const resendVerificationController = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({
            success: false,
            message: "Email is required."
        });
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found."
            });
        }

        if (user.isVerified) {
            return res.status(400).json({
                success: false,
                message: "User already verified."
            });
        }

        // Generate a new verification token
        const newToken = generateVerificationToken();
        const verifyLink = `${process.env.CLIENT_URL}/verify-user?token=${newToken}`;

        // Save the token and its expiration date to the user model (optional step)
        user.verificationToken = newToken;
        user.verificationTokenExpiration = Date.now() + 3600000; // 1 hour expiration
        await user.save();

        // Send the new verification email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: "Verify your email - Auth Template",
            html: `
                <h1>Hi ${user.name},</h1>
                <p>Please verify your email by clicking the button below:</p>
                <a href="${verifyLink}" style="padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px;">Verify Email</a>
            `
        };

        await transporter.sendMail(mailOptions);

        return res.status(200).json({
            success: true,
            message: "A new verification email has been sent. Please check your inbox."
        });

    } catch (err) {
        return res.status(500).json({
            success: false,
            message: err.message
        });
    }
};