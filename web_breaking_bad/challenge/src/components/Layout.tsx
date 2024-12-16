import { Link, Outlet } from 'react-router-dom';
import { ModeToggle } from '@/components/mode-toggle';
import { LayoutDashboard, LineChart, Wallet, Users, Send } from 'lucide-react';
import LogoutButton from '@/components/LogoutButton';

export default function Layout() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <nav className="border-b bg-secondary text-secondary-foreground">
        <div className="flex h-16 items-center px-6 max-w-[2000px] mx-auto">
          <div className="flex items-center space-x-6">
            <Link to="/" className="font-bold text-xl">
              CryptoX
            </Link>
            <Link to="/" className="flex items-center text-sm font-medium transition-colors hover:text-primary">
              <LayoutDashboard className="h-4 w-4 mr-2" />
              Dashboard
            </Link>
            <Link to="/market" className="flex items-center text-sm font-medium transition-colors hover:text-primary">
              <LineChart className="h-4 w-4 mr-2" />
              Market
            </Link>
            <Link to="/portfolio" className="flex items-center text-sm font-medium transition-colors hover:text-primary">
              <Wallet className="h-4 w-4 mr-2" />
              Portfolio
            </Link>
            <Link to="/friends" className="flex items-center text-sm font-medium transition-colors hover:text-primary">
              <Users className="h-4 w-4 mr-2" />
              Friends
            </Link>
            <Link to="/transactions" className="flex items-center text-sm font-medium transition-colors hover:text-primary">
              <Send className="h-4 w-4 mr-2" />
              Transactions
            </Link>
          </div>

          <div className="ml-auto flex items-center space-x-4">
            <ModeToggle />
            <LogoutButton />
          </div>
        </div>
      </nav>

      <main className="px-6 py-6 max-w-[2000px] mx-auto w-full">
        <Outlet />
      </main>
    </div>
  );
}