import React from 'react';
import { useNavigate } from 'react-router-dom';
import LogoutButton from '../components/LogoutButton';
import { useUser } from '../contexts/UserContext';

const Home = () => {
    const navigate = useNavigate();
    const { user, loading, fetchUserDetails, setUser } = useUser();

    return (
        <div className="bg-green-500 p-4 min-h-screen">
            <h1 className="text-xl font-semibold mb-4">Home</h1>

            {loading ? (
                <p>Loading user details...</p>
            ) : user ? (
                <div className="space-y-4">
                    <p>Name: {user.name}</p>
                    <p>Email: {user.email}</p>
                    <div className="flex gap-2">
                        <LogoutButton onLogout={() => setUser(null)} />
                        <button
                            onClick={fetchUserDetails}
                            className="px-4 py-2 bg-yellow-500 text-black rounded hover:bg-yellow-600"
                        >
                            Refetch User Data
                        </button>
                    </div>
                </div>
            ) : (
                <div className="space-x-4">
                    <button
                        onClick={() => navigate("/login")}
                        className="px-4 py-2 bg-black text-white rounded hover:bg-gray-800"
                    >
                        Login
                    </button>
                    <button
                        onClick={() => navigate("/register")}
                        className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                    >
                        Register
                    </button>
                    <button
                        onClick={fetchUserDetails}
                        className="px-4 py-2 bg-yellow-500 text-black rounded hover:bg-yellow-600"
                    >
                        Refetch User Data
                    </button>
                </div>
            )}
        </div>
    );
};

export default Home;
