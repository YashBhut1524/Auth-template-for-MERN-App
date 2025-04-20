import jwt from "jsonwebtoken";

const SECRET_KEY = process.env.SECRET_KEY_ACCESS_TOKEN;

function AuthMiddleware(req, res, next) {
    const token = req.cookies?.accessToken;

    if (!token) {
        return res.status(401).json({
            success: false,
            message: "No access token found in cookies",
        });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        console.log("decoded:", decoded);

        if (decoded?.id && decoded?.email) {
            // Attach the decoded user info to req.user
            req.user = {
                id: decoded.id,
                email: decoded.email,
            };

            // Get userId and userEmail like this in next()
            // const userId = req.user.id; // use only id
            // or
            // const userEmail = req.user.email; // if needed
            
            next();

        } else {
            return res.status(401).json({
                success: false,
                message: "Not authorized: token is missing required fields",
            });
        }
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401).json({
                success: false,
                message: "Access token expired",
                error: error.message,
            });
        }
        return res.status(401).json({
            success: false,
            message: "Invalid token",
            error: error.message,
        });
    }
}

export default AuthMiddleware;
