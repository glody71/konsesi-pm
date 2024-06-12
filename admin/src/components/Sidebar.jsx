// src/components/Sidebar.js
import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { HiMenuAlt3 } from "react-icons/hi";
import { RxDashboard, RxTable } from "react-icons/rx";
import { FiLogOut } from 'react-icons/fi';

const Sidebar = () => {
    const handleLogout = () => {
        localStorage.removeItem('token');
        window.location.href = '/login';
    };

    const menus = [
        { name: "Dashboard", link: '/', icon: RxDashboard },
        { name: "Profile", link: '/profile', icon: RxTable },
    ];

    const [isOpen, setIsOpen] = useState(true);
    const [isMobileOpen, setIsMobileOpen] = useState(false);

    return (
        <div className='flex h-screen'>
            {/* Sidebar */}
            <div className={`bg-white shadow-lg min-h-screen ${isOpen ? 'w-64' : 'w-16'} duration-500 px-4 
                ${isMobileOpen ? 'fixed z-50 w-64' : 'hidden'} sm:flex sm:flex-col`}>
                {/* Toggle Button */}
                <div className='py-3 flex justify-end'>
                    <HiMenuAlt3
                        size={26}
                        className='cursor-pointer sm:hidden'
                        onClick={() => setIsMobileOpen(!isMobileOpen)}
                    />
                    <HiMenuAlt3
                        size={26}
                        className='cursor-pointer hidden sm:block'
                        onClick={() => setIsOpen(!isOpen)}
                    />
                </div>

                {/* Menu Items */}
                <div className='mt-8 flex flex-col gap-4 relative'>
                    {menus.map((menu, i) => (
                        <Link to={menu.link}
                            key={i}
                            className='flex items-center text-sm gap-3.5 font-semibold p-2 hover:bg-gray-200 transition duration-200 rounded group'
                        >
                            <div>
                                {React.createElement(menu.icon, { size: "20" })}
                            </div>
                            <h2 className={`whitespace-pre duration-300 ${!isOpen && 'opacity-0 translate-x-4 overflow-hidden'}`}>
                                {menu.name}
                            </h2>
                            <h2 className={`${isOpen && "hidden"} absolute left-48 bg-white font-semibold whitespace-pre text-gray-900 rounded-md drop-shadow-lg px-0 py-0 group-hover:px-2 group-hover:py-1 group-hover:left-14 group-hover:duration-300 w-0 overflow-hidden group-hover:w-fit`}>
                                {menu.name}
                            </h2>
                        </Link>
                    ))}
                </div>

                {/* Logout Button */}
                <div className='mt-auto mb-4 flex flex-col gap-4 relative'>
                    <button
                        onClick={handleLogout}
                        className='flex items-center text-sm gap-3.5 font-semibold p-2 hover:bg-red-200 transition duration-200 rounded group w-full'
                    >
                        <FiLogOut size={20} className={`${isOpen ? 'block' : 'block min-w-[2rem]'}`} />
                        <h2 className={`whitespace-pre duration-300 ${!isOpen && 'opacity-0 translate-x-4 overflow-hidden'}`}>
                            Logout
                        </h2>
                        <h2 className={`${isOpen && "hidden"} absolute left-48 bg-white font-semibold whitespace-pre text-gray-900 rounded-md drop-shadow-lg px-0 py-0 group-hover:px-2 group-hover:py-1 group-hover:left-14 group-hover:duration-300 w-0 overflow-hidden group-hover:w-fit`}>
                            Logout
                        </h2>
                    </button>
                </div>
            </div>

            {/* Overlay for Small Screens */}
            {isMobileOpen && (
                <div
                    className="fixed inset-0 bg-black opacity-50 z-40 sm:hidden"
                    onClick={() => setIsMobileOpen(false)}
                ></div>
            )}
        </div>
    );
};

export default Sidebar;
