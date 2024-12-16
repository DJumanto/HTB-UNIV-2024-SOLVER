import React, { useEffect, useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';
import axios from 'axios';
import { Skeleton } from '@/components/ui/skeleton';

const ProtectedRoute: React.FC<{ children: JSX.Element }> = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [loading, setLoading] = useState(true);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    const validateToken = async () => {
      const token = localStorage.getItem('jwt');

      if (!token) {
        console.warn('No JWT found in localStorage');
        setLoading(false);
        navigate('/login', { replace: true, state: { from: location } });
        return;
      }

      try {
        const response = await axios.get('/api/dashboard', {
          headers: {
            Authorization: `Bearer ${token}`,
          },
          validateStatus: (status) => status === 200,
        });

        if (response.status === 200) {
          setIsAuthenticated(true);
        } else {
          throw new Error('Invalid response status');
        }
      } catch (err) {
        console.error('Token validation failed:', err);
        localStorage.removeItem('jwt');
        navigate('/login', {
          replace: true,
          state: { from: location, error: 'Session expired. Please log in again.' },
        });
      } finally {
        setLoading(false);
      }
    };

    validateToken();
  }, [navigate, location]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Skeleton className="w-[200px] h-[20px]" />
      </div>
    );
  }

  return isAuthenticated ? children : <Navigate to="/login" replace state={{ from: location }} />;
};

export default ProtectedRoute;