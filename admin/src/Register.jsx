// src/Register.js
import React, { useState } from 'react';
import axios from 'axios';

const Register = () => {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    const handleRegister = async () => {
        try {
            await axios.post('http://localhost:5000/register', { username, password });
            alert('Registration successful');
            window.location.href = '/login';
        } catch (error) {
            alert('Registration failed');
        }
    };

    return (
        <div className="flex justify-center items-center h-screen bg-gray-100">
            <div className="bg-white p-8 rounded shadow-md w-96">
                <h2 className="text-2xl font-bold mb-6">Register</h2>
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
                    onClick={handleRegister}
                    className="w-full p-2 bg-green-600 text-white rounded hover:bg-green-700"
                >
                    Register
                </button>
            </div>
        </div>
    );
};

export default Register;
