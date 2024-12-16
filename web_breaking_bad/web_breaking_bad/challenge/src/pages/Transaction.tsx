import React, { useState, useEffect } from 'react';
import { useFriends } from '@/context/FriendsContext';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import { Send, Loader2, Coins, Users, DollarSign } from 'lucide-react';
import axios from 'axios';

interface Coin {
  symbol: string;
  name: string;
  availableBalance: number;
  icon?: React.ReactNode;
}

export default function Transaction() {
  const { friends } = useFriends();
  const [coins, setCoins] = useState<Coin[]>([]);
  const [selectedFriend, setSelectedFriend] = useState('');
  const [selectedCoin, setSelectedCoin] = useState('');
  const [amount, setAmount] = useState('');
  const [otp, setOtp] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [walletBalance, setWalletBalance] = useState<number | null>(null);

  useEffect(() => {
    const fetchCoins = async () => {
      try {
        const token = localStorage.getItem('jwt');
        const balanceResponse = await axios.get('/api/crypto/balance', {
          headers: { Authorization: `Bearer ${token}` },
        });

        const enrichedCoins = balanceResponse.data.map((coin: Coin) => ({
          ...coin,
          icon: <DollarSign className="h-4 w-4 text-green-600" />,
        }));

        setCoins(enrichedCoins);
      } catch (err) {
        setError('Failed to load available coins and balances');
      }
    };

    fetchCoins();
  }, []);

  useEffect(() => {
    const selected = coins.find((coin) => coin.symbol === selectedCoin);
    setWalletBalance(selected ? selected.availableBalance : null);
  }, [selectedCoin, coins]);

  const handleTransaction = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('jwt');
      await axios.post(
        '/api/crypto/transaction',
        {
          to: selectedFriend,
          coin: selectedCoin,
          amount: parseFloat(amount),
          otp: [otp],
        },
        { headers: { Authorization: `Bearer ${token}` } }
      );
  
      setSuccess('Transaction completed successfully');
      setError('');
      setIsModalOpen(false);
  
      setSelectedFriend('');
      setSelectedCoin('');
      setAmount('');
      setOtp('');
    } catch (err) {
      setError(err.response?.data?.error || 'Transaction failed');
      setSuccess('');
      setIsModalOpen(false);
    } finally {
      setLoading(false);
    }
  };  

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFriend || !selectedCoin || !amount) {
      setError('Please fill in all fields');
      return;
    }
    if (walletBalance !== null && parseFloat(amount) > walletBalance) {
      setError('Insufficient balance for this transaction');
      return;
    }
    setError('');
    setIsModalOpen(true);
  };

  return (
    <div className="container mx-auto p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold">Send Transaction</h1>
      </div>

      <div className="mb-6 p-4 bg-blue-50 border-l-4 border-blue-500 text-blue-700">
        <p className="text-sm">
          <strong>Note:</strong> Transactions are limited to friends. Global transfers are disabled for security reasons.
        </p>
      </div>

      <Card className="p-6 bg-background shadow-lg">
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-2">
            <label className="text-sm font-medium flex items-center gap-2">
              <Users className="h-4 w-4" />
              Select Friend
            </label>
            <Select value={selectedFriend} onValueChange={setSelectedFriend}>
              <SelectTrigger>
                <SelectValue placeholder="Select a friend" />
              </SelectTrigger>
              <SelectContent className="bg-black text-white">
                {friends.length > 0 ? (
                  friends.map((friend) => (
                    <SelectItem key={`friend-${friend.email}`} value={friend.email}>
                      {friend.email}
                    </SelectItem>
                  ))
                ) : (
                  <SelectItem disabled>No friends available</SelectItem>
                )}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium flex items-center gap-2">
              <Coins className="h-4 w-4" />
              Select Coin
            </label>
            <Select value={selectedCoin} onValueChange={setSelectedCoin}>
              <SelectTrigger>
                <SelectValue placeholder="Select a coin" />
              </SelectTrigger>
              <SelectContent className="bg-black text-white">
                {coins.length > 0 ? (
                  coins.map((coin) => (
                    <SelectItem key={`coin-${coin.symbol}`} value={coin.symbol}>
                      <div className="flex items-center gap-2">
                        {coin.icon}
                        <span>
                          {coin.name} ({coin.symbol})
                        </span>
                      </div>
                    </SelectItem>
                  ))
                ) : (
                  <SelectItem disabled>No coins available</SelectItem>
                )}
              </SelectContent>
            </Select>
            {walletBalance !== null && (
              <p className="text-sm text-gray-600">
                Available Balance: <strong>{walletBalance}</strong>
              </p>
            )}
          </div>

          <div className="space-y-2">
            <label className="text-sm font-medium">Amount</label>
            <Input
              type="number"
              placeholder="Enter amount"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              min="0"
              step="0.000001"
            />
          </div>

          {error && (
            <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded">
              {error}
            </div>
          )}
          {success && (
            <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded">
              {success}
            </div>
          )}

          <Button
            type="submit"
            className="w-full flex items-center justify-center gap-2"
            disabled={loading || !selectedFriend || !selectedCoin || !amount}
          >
            {loading ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <Send className="h-4 w-4" />
            )}
            Send Transaction
          </Button>
        </form>
      </Card>

      <Dialog open={isModalOpen} onOpenChange={setIsModalOpen}>
        <DialogContent className="bg-black text-white">
          <DialogHeader>
            <DialogTitle>Enter OTP</DialogTitle>
            <DialogDescription>
              Please enter your one-time password to confirm the transaction.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 pt-4">
            <Input
              type="text"
              placeholder="Enter OTP"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
            />
            <div className="flex justify-end space-x-2">
              <Button variant="outline" onClick={() => setIsModalOpen(false)}>
                Cancel
              </Button>
              <Button
                onClick={handleTransaction}
                disabled={!otp || loading}
                className="flex items-center gap-2"
              >
                {loading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Send className="h-4 w-4" />
                )}
                Confirm
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}