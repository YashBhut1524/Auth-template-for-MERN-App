import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../utils/api";

const ProtectedRedirect = ({ children }) => {
    const [checking, setChecking] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        const checkAuth = async () => {
            try {
                const response = await api.get("/api/user/is-auth");
                console.log("Auth check result:", response.data);

                if (response.data.success) {
                    // ✅ Authenticated, redirect away from /login or /register
                    navigate("/", { replace: true });
                } else {
                    // ❌ Not authenticated, allow access to login/register
                    setChecking(false);
                }
            } catch (err) {
                console.warn("Error during auth check:", err?.response?.data || err.message);
                setChecking(false); // Assume unauthenticated if error
            }
        };

        checkAuth();
    }, [navigate]);

    if (checking) {
        return (
            <div className="flex justify-center items-center h-screen">
                <p className="text-lg font-semibold">Checking authentication...</p>
            </div>
        );
    }

    return children;
};

export default ProtectedRedirect;
