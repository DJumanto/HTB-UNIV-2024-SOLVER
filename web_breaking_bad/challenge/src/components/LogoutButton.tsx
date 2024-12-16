import React from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Button } from '@/components/ui/button';

const LogoutButton: React.FC<{ redirectTo?: string }> = ({ redirectTo = '/login' }) => {
    const navigate = useNavigate();

    const handleLogout = async () => {

        const token = localStorage.getItem('jwt');
        if (!token) {
            navigate(redirectTo);
            return;
        }

        localStorage.removeItem('jwt');
        navigate(redirectTo);
    };

    return (
        <Button
            onClick={handleLogout}
            variant="destructive"
            className="px-4 py-2"
        >
            Logout
        </Button>
    );
};

export default LogoutButton;