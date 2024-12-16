import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { BrowserRouter, Route, Routes } from 'react-router-dom';
import { ThemeProvider } from '@/components/theme-provider';
import Layout from '@/components/Layout';
import Dashboard from '@/pages/Dashboard';
import Login from '@/pages/Login';
import Register from '@/pages/Register';
import Market from '@/pages/Market';
import Portfolio from '@/pages/Portfolio';
import Transaction from '@/pages/Transaction';
import Friends from '@/pages/Friends';
import ProtectedRoute from '@/components/ProtectedRoute';
import { FriendsProvider } from '@/context/FriendsContext';
import MarketingCTA from '@/components/MarketingCTA';

const queryClient = new QueryClient();

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider defaultTheme="dark" storageKey="vite-ui-theme">
        <BrowserRouter>
          <FriendsProvider>
            <div className="relative">
              <MarketingCTA />
              <Routes>
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />

                <Route path="/" element={<Layout />}>
                  <Route
                    index
                    element={
                      <ProtectedRoute>
                        <Dashboard />
                      </ProtectedRoute>
                    }
                  />
                  <Route
                    path="dashboard"
                    element={
                      <ProtectedRoute>
                        <Dashboard />
                      </ProtectedRoute>
                    }
                  />
                  <Route
                    path="market"
                    element={
                      <ProtectedRoute>
                        <Market />
                      </ProtectedRoute>
                    }
                  />
                  <Route
                    path="portfolio"
                    element={
                      <ProtectedRoute>
                        <Portfolio />
                      </ProtectedRoute>
                    }
                  />
                  <Route
                    path="friends"
                    element={
                      <ProtectedRoute>
                        <Friends />
                      </ProtectedRoute>
                    }
                  />
                  <Route
                    path="transactions"
                    element={
                      <ProtectedRoute>
                        <Transaction />
                      </ProtectedRoute>
                    }
                  />
                </Route>
              </Routes>
            </div>
          </FriendsProvider>
        </BrowserRouter>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;