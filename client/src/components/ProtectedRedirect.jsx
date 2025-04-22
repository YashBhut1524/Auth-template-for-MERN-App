import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "../utils/api";

const ProtectedRedirect = ({ children }) => {
    const [checking, setChecking] = useState(true);
    const navigate = useNavigate();

    useEffect(() => {
        let isMounted = true;

        api
            .get("/api/auth")
            .then(() => {
                if (isMounted) {
                    console.log("User is authenticated. Redirecting...");
                    navigate("/");
                }
            })
            .catch((err) => {
                console.log("User is not authenticated.", err);
                if (isMounted) {
                    setChecking(false); // allow render
                }
            });

        return () => {
            isMounted = false;
        };
    }, [navigate]);

    if (checking) {
        return <div className="text-center py-10">Loading...</div>;
    }

    return children;
};

export default ProtectedRedirect;
