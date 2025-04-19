// routes/index.jsx
import { createBrowserRouter } from "react-router-dom";
import App from "../App.jsx";
import Home from "../pages/Home.jsx";
import VerifyEmail from "../pages/VerifyEmail.jsx";

const router = createBrowserRouter([
    {
        path: "/",
        element: <App />,
        children: [
            { path: "", element: <Home /> },
            { path: "verify-user", element: <VerifyEmail /> },
        ]
    }
]);

export default router;
