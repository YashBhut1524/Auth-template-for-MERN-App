import jwt from "jsonwebtoken";

export const generateRefreshToken = (user) => {
    return jwt.sign(
        { id: user._id },
        process.env.SECRET_KEY_REFRESH_TOKEN,
        { expiresIn: "7d" }
    );
};

// export const verifyRefreshToken = (token) => {
//     try {
//         return jwt.verify(token, process.env.SECRET_KEY_REFRESH_TOKEN);
//     } catch (err) {
//         throw new Error("Invalid or expired refresh token");
//     }
// };
