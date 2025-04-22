import { createBrowserRouter } from "react-router-dom"
import Home from "../pages/Home.jsx";
import VerifyEmail from "../pages/VerifyEmail.jsx";
import RegisterPage from "../pages/RegisterPage.jsx";
import LoginPage from "../pages/LoginPage.jsx";
import ProtectedRedirect from "../components/ProtectedRedirect.jsx";
import App from "../App.jsx"

const router = createBrowserRouter([
    {
        path: "/",
        element: <App />,
        children: [
            { path: "", element: <Home /> },
            { path: "verify-user", element: <VerifyEmail /> },
            {
                path: "register",
                element: (
                    <ProtectedRedirect>
                        <RegisterPage />
                    </ProtectedRedirect>
                ),
            },
            {
                path: "login",
                element: (
                    <ProtectedRedirect>
                        <LoginPage />
                    </ProtectedRedirect>
                ),
            },
        ],
    },
]);

export default router;
