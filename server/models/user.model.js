import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    passResetOtp: {
        type: String,
        default: ""
    },
    passResetOtpExpiresAt: {
        type: Number,
        default: 0
    },
}, { timestamps: true })

const userModel = mongoose.model.user || mongoose.model("User", userSchema)

export default userModel;