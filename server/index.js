import express from "express"
import cors from "cors"
import "dotenv/config"
import cookieParser from "cookie-parser"
import connectDB from "./config/mongodb.js"
import userRoutes from "./routes/user.route.js"

const app = express()
const port = process.env.PORT || 3000
connectDB()

app.use(express.json())
app.use(cookieParser())
app.use(cors({
    origin: "http://localhost:5173",
    credentials: true
}))

// API Endpoints
app.get('/', (req, res) => res.send("Server Started"))
app.use("/api/user", userRoutes)

app.listen(port, () => {
    console.log(`Server is running on PORT:${port}`);
})

