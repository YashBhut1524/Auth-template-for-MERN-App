import { Router } from "express";
import { 
    loginController, 
    logoutController, 
    registerController, 
    verifyUserController, 
    resendVerificationController,
    isAuthenticated,
} from "../controllers/user.controller.js";
import AuthMiddleware from "../middleware/authMiddleware.js";

const userRoutes = Router();

userRoutes.post("/register", registerController);
userRoutes.get("/verify-user/:token", verifyUserController);
userRoutes.post("/resend-verification", resendVerificationController);
userRoutes.post("/login", loginController);
userRoutes.post("/logout", logoutController);
userRoutes.get("/is-auth", AuthMiddleware, isAuthenticated);

export default userRoutes;
