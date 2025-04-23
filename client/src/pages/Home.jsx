import React, { useEffect, useState } from 'react';
import api from '../utils/api'; // assuming this is your axios instance

const Home = () => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true); // Start loading as true

    useEffect(() => {
        const fetchUserDetails = async () => {
            try {
                const res = await api.get("/api/user/my-details");
                setUser(res.data.data);
            } catch (error) {
                console.error("Failed to fetch user details:", error);
            } finally {
                setLoading(false); // Set loading to false when done
            }
        };

        fetchUserDetails();
    }, []);

    return (
        <div className='bg-green-500 p-4'>
            <h1>Home</h1>
            {loading ? (
                <p>Loading user details...</p>
            ) : user ? (
                <div>
                    <p>Name: {user.name}</p>
                    <p>Email: {user.email}</p>
                </div>
            ) : (
                <p>Failed to load user details</p> // Show error message if user is null
            )}
        </div>
    );
};

export default Home;
