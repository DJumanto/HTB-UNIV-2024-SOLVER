// components/Market.tsx
import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';
import { Card } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { ArrowUpIcon, ArrowDownIcon } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

type Crypto = {
  symbol: string;
  name: string;
  price: number;
  change24h: number;
};

type HistoryData = {
  time: string;
  price: number;
};

export default function Market() {
  const [selectedCoin, setSelectedCoin] = useState<Crypto | null>(null);
  const [historyData, setHistoryData] = useState<HistoryData[]>([]);
  const [period, setPeriod] = useState<number>(7); // Default to 1 week
  const [error, setError] = useState<string>('');

  const { data: cryptoData, isLoading: cryptoLoading } = useQuery<Crypto[]>({
    queryKey: ['crypto'],
    queryFn: async () => {
      const token = localStorage.getItem('jwt');
      if (!token) throw new Error('No access token found. Please log in.');

      const { data } = await axios.get<Crypto[]>('/api/crypto', {
        headers: { Authorization: `Bearer ${token}` },
      });
      return data;
    },
  });

  const fetchHistoryData = async (symbol: string, selectedPeriod: number) => {
    try {
      const token = localStorage.getItem('jwt');
      if (!token) throw new Error('No access token found. Please log in.');

      const { data } = await axios.get<HistoryData[]>(`/api/crypto/${symbol}/history?period=${selectedPeriod}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setHistoryData(data);
    } catch (err) {
      setError('Failed to fetch historical data.');
    }
  };

  if (cryptoLoading) {
    return (
      <div className="min-h-screen bg-background text-white flex items-center justify-center">
        Loading...
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-background text-red-500 flex items-center justify-center">
        {error}
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Market</h1>

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Symbol</TableHead>
              <TableHead className="text-right">Price</TableHead>
              <TableHead className="text-right">24h Change</TableHead>
              <TableHead className="text-right">Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {cryptoData?.map((crypto) => (
              <TableRow key={crypto.symbol}>
                <TableCell className="font-medium">{crypto.name}</TableCell>
                <TableCell>{crypto.symbol}</TableCell>
                <TableCell className="text-right">${crypto.price.toLocaleString()}</TableCell>
                <TableCell className="text-right">
                  <span
                    className={`flex items-center justify-end ${
                      crypto.change24h >= 0 ? 'text-green-500' : 'text-red-500'
                    }`}
                  >
                    {crypto.change24h >= 0 ? (
                      <ArrowUpIcon className="h-4 w-4 mr-1" />
                    ) : (
                      <ArrowDownIcon className="h-4 w-4 mr-1" />
                    )}
                    {Math.abs(crypto.change24h)}%
                  </span>
                </TableCell>
                <TableCell className="text-right">
                  <button
                    onClick={() => {
                      setSelectedCoin(crypto);
                      fetchHistoryData(crypto.symbol, period);
                    }}
                    className="text-primary hover:underline"
                  >
                    View History
                  </button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Card>

      {selectedCoin && (
        <Card className="p-6">
          <h2 className="text-xl font-bold mb-4">{selectedCoin.name} Price History</h2>
          <div className="flex justify-between mb-4">
            <button
              onClick={() => {
                setPeriod(7);
                fetchHistoryData(selectedCoin.symbol, 7);
              }}
              className={`px-4 py-2 rounded ${
                period === 7 ? 'bg-blue-500 text-white' : 'bg-gray-200 text-black'
              }`}
            >
              1 Week
            </button>
            <button
              onClick={() => {
                setPeriod(30);
                fetchHistoryData(selectedCoin.symbol, 30);
              }}
              className={`px-4 py-2 rounded ${
                period === 30 ? 'bg-blue-500 text-white' : 'bg-gray-200 text-black'
              }`}
            >
              1 Month
            </button>
            <button
              onClick={() => {
                setPeriod(365);
                fetchHistoryData(selectedCoin.symbol, 365);
              }}
              className={`px-4 py-2 rounded ${
                period === 365 ? 'bg-blue-500 text-white' : 'bg-gray-200 text-black'
              }`}
            >
              1 Year
            </button>
          </div>
          <div className="h-[400px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={historyData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Line type="monotone" dataKey="price" stroke="#3b82f6" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>
      )}
    </div>
  );
}