import axios from "axios";
import userModel from "../models/user.model.js";
import { generateAccessToken, generateRefreshToken } from "../utils/generateJwtTokens.js";
import { accessCookieOptions, refreshCookieOptions } from "../utils/cookieOptions.js";

const FRONTEND_URL = process.env.CLIENT_URL;
const SERVER_URL = process.env.SERVER_URL;

const REDIRECT_SUCCESS = `${FRONTEND_URL}/oauth-success`;
const REDIRECT_ERROR = `${FRONTEND_URL}/login?error=true`;

export const googleOAuthController = (req, res) => {
    const redirectUri = `${SERVER_URL}/api/auth/google/callback`;

    const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    url.searchParams.set("client_id", process.env.GOOGLE_CLIENT_ID);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", "openid email profile");
    url.searchParams.set("access_type", "offline");
    url.searchParams.set("prompt", "consent"); // forces refresh token

    res.redirect(url.toString());
};

export const googleOAuthCallbackController = async (req, res) => {
    const code = req.query.code;

    if (!code) {
        console.error("No code received in callback");
        return res.redirect(REDIRECT_ERROR);
    }

    try {
        const redirectUri = `${SERVER_URL}/api/auth/google/callback`;

        const tokenResponse = await axios.post(
            "https://oauth2.googleapis.com/token",
            new URLSearchParams({
                code,
                client_id: process.env.GOOGLE_CLIENT_ID,
                client_secret: process.env.GOOGLE_CLIENT_SECRET,
                redirect_uri: redirectUri,
                grant_type: "authorization_code",
            }),
            {
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            }
        );

        const { access_token } = tokenResponse.data;

        const { data: userInfo } = await axios.get("https://www.googleapis.com/oauth2/v2/userinfo", {
            headers: { Authorization: `Bearer ${access_token}` },
        });

        const { email, name, picture } = userInfo;

        let user = await userModel.findOne({ email });

        if (!user) {
            user = await userModel.create({
                email,
                name,
                picture,
                isVerified: true,
                password: null,
                provider: "google",
            });
        }

        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);

        res.cookie("accessToken", accessToken, accessCookieOptions);
        res.cookie("refreshToken", refreshToken, refreshCookieOptions);

        return res.redirect(REDIRECT_SUCCESS);
    } catch (err) {
        console.error("Google OAuth Error:", err.message);
        return res.redirect(REDIRECT_ERROR);
    }
};
