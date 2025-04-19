import jwt from "jsonwebtoken";

export const generateAccessToken = (user) => {
    return jwt.sign(
        { id: user._id, email: user.email }, // Add minimal user data
        process.env.SECRET_KEY_ACCESS_TOKEN, // Secret for access token
        { expiresIn: "15m" } // Expiry time for access token
    );
};

// export const verifyAccessToken = (token) => {
//     try {
//         return jwt.verify(token, process.env.SECRET_KEY_ACCESS_TOKEN); // Verifying with secret
//     } catch (err) {
//         throw new Error("Invalid or expired access token");
//     }
// };
