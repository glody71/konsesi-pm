// src/components/Layout.js
import React from 'react';
import Sidebar from './Sidebar';

const Layout = ({ children }) => {
    return (
        <div className="flex">
            <Sidebar />
            <div className="flex-grow p-6 bg-gray-100 min-h-screen">
                {children}
            </div>
        </div>
    );
};

export default Layout;
