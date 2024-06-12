// src/Login.js
import React, { useState } from 'react';
import axios from 'axios';

const Login = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    const handleLogin = async () => {
        try {
            const response = await axios.post('http://localhost:5000/login', { username, password });
            localStorage.setItem('token', response.data.token);
            alert('Login successful');
            window.location.href = '/dashboard';
        } catch (error) {
            alert('Login failed');
        }
    };

    return (
        <div className="flex justify-center items-center h-screen bg-gray-100">
            <div className="bg-white p-8 rounded shadow-md w-96">
                <h2 className="text-2xl font-bold mb-6 flex justify-center">Login</h2>
                <input
                    type="text"
                    placeholder="Username"
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    className="block w-full p-2 mb-4 border rounded"
                />
                <input
                    type="password"
                    placeholder="Password"
                    value={password}
                    onChange={e => setPassword(e.target.value)}
                    className="block w-full p-2 mb-4 border rounded"
                />
                <button
                    onClick={handleLogin}
                    className="w-full p-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                    type='submit'
                >
                    Login
                </button>
            </div>
        </div>
    );
};

export default Login;
