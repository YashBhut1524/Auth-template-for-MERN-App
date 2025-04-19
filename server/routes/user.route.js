import {Router} from "express"
import { 
    loginController, 
    logoutController, 
    registerController 
} from "../controllers/user.controller.js"

const userRoutes = Router()

userRoutes.post("/register", registerController)
userRoutes.post("/login", loginController)
userRoutes.post("/logout", logoutController)


export default userRoutes