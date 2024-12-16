import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

const Login: React.FC = () => {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const navigate = useNavigate();
    const location = useLocation();

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password }),
            });

            if (response.ok) {
                const data = await response.json();
                if (data.token) {
                    localStorage.setItem('jwt', data.token);
                    navigate('/dashboard');
                } else {
                    setError('Unexpected server response: Missing token.');
                }
            } else {
                const data = await response.json();
                setError(data.error || 'Invalid credentials');
            }
        } catch (err) {
            console.error('Login error:', err);
            setError('An error occurred. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-background text-white">
            <div className="max-w-md w-full bg-gray-800 rounded-lg shadow-lg p-8">
                <div className="text-center mb-8">
                    <img
                        src="/logo.png"
                        alt="CryptoX Logo"
                        className="w-24 h-24 mx-auto mb-4"
                    />
                    <h1 className="text-3xl font-bold text-purple-400">
                        Welcome Back to CryptoX
                    </h1>
                    <p className="text-sm text-gray-300 mt-2">
                        Log in to manage your crypto portfolio and explore the latest market trends.
                    </p>
                </div>
                <form onSubmit={handleLogin} className="space-y-6">
                    <div>
                        <label
                            htmlFor="email"
                            className="block text-sm font-medium text-gray-300"
                        >
                            Email
                        </label>
                        <Input
                            id="email"
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            placeholder="Enter your email"
                            required
                            className="mt-1 w-full"
                        />
                    </div>
                    <div>
                        <label
                            htmlFor="password"
                            className="block text-sm font-medium text-gray-300"
                        >
                            Password
                        </label>
                        <Input
                            id="password"
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            placeholder="Enter your password"
                            required
                            className="mt-1 w-full"
                        />
                    </div>
                    <Button
                        type="submit"
                        className="w-full bg-purple-600 hover:bg-purple-700 text-white font-semibold py-2 rounded"
                        disabled={loading}
                    >
                        {loading ? 'Logging in...' : 'Login'}
                    </Button>
                </form>
                {error && (
                    <div className="mt-4 bg-red-50 border-l-4 border-red-500 text-red-700 p-4 rounded">
                        <p className="text-sm">{error}</p>
                    </div>
                )}
                {location.state?.error && (
                    <div className="mt-4 bg-yellow-50 border-l-4 border-yellow-500 text-yellow-700 p-4 rounded">
                        <p className="text-sm">{location.state.error}</p>
                    </div>
                )}
                <div className="mt-6 text-center">
                    <p className="text-sm text-gray-300">
                        Don’t have an account?{' '}
                        <button
                            onClick={() => navigate('/register')}
                            className="text-purple-400 hover:underline font-medium"
                        >
                            Register here
                        </button>
                    </p>
                </div>
            </div>
        </div>
    );
};

export default Login;