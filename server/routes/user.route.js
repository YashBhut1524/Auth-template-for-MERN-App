import { Router } from "express";
import { 
    loginController, 
    logoutController, 
    registerController, 
    verifyUserController, 
    resendVerificationController,
} from "../controllers/user.controller.js";

const userRoutes = Router();

userRoutes.post("/register", registerController);
userRoutes.get("/verify-user/:token", verifyUserController);
userRoutes.post("/resend-verification", resendVerificationController);
userRoutes.post("/login", loginController);
userRoutes.post("/logout", logoutController);

export default userRoutes;
