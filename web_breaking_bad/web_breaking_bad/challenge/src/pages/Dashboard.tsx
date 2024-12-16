import React, { useState, useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';
import { Card } from '@/components/ui/card';
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

export default function Dashboard() {
  const [selectedSymbol, setSelectedSymbol] = useState<string>('CLCR'); // Default to Cluster Credit's symbol
  const [period, setPeriod] = useState(24); // Default to 24h
  const [historyData, setHistoryData] = useState<HistoryData[]>([]);
  const [error, setError] = useState('');
  const [flag, setFlag] = useState<string | null>(null); // Store the flag
  const [cryptoData, setCryptoData] = useState<Crypto[]>([]); // Store crypto data
  const [selectedCrypto, setSelectedCrypto] = useState<Crypto | null>(null); // Store selected crypto details

  const fetchCryptoData = async () => {
    const token = localStorage.getItem('jwt');
    if (!token) throw new Error('No access token found. Please log in.');

    const { data } = await axios.get('/api/crypto', {
      headers: { Authorization: `Bearer ${token}` },
    });
    setCryptoData(data);

    const defaultCoin = data.find((crypto: Crypto) => crypto.symbol === 'CLCR');
    setSelectedCrypto(defaultCoin || null);
  };

  const fetchDashboardData = async () => {
    const token = localStorage.getItem('jwt');
    if (!token) throw new Error('No access token found. Please log in.');

    const { data } = await axios.get('/api/dashboard', {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (data.flag) {
      setFlag(data.flag);
    }
  };

  const fetchHistoryData = async (symbol: string, period: number) => {
    try {
      const token = localStorage.getItem('jwt');
      if (!token) throw new Error('No access token found. Please log in.');

      const { data } = await axios.get(`/api/crypto/${symbol}/history?period=${period}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setHistoryData(data);
    } catch (err) {
      console.error('Error fetching historical data:', err);
      setError('Failed to fetch historical data.');
    }
  };

  useEffect(() => {
    const interval = setInterval(() => {
      setCryptoData((prevData) =>
        prevData.map((crypto) => ({
          ...crypto,
          change24h: (Math.random() * 2 - 1).toFixed(2),
          price: parseFloat((crypto.price * (1 + Math.random() * 0.02 - 0.01)).toFixed(2)),
        }))
      );
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    fetchCryptoData();
    fetchDashboardData();
  }, []);

  useEffect(() => {
    if (selectedSymbol) {
      fetchHistoryData(selectedSymbol, period);

      const coin = cryptoData.find((crypto) => crypto.symbol === selectedSymbol);
      setSelectedCrypto(coin || null);
    }
  }, [selectedSymbol, period, cryptoData]);

  if (!cryptoData.length) {
    return <div className="min-h-screen bg-background text-white flex items-center justify-center">Loading...</div>;
  }

  if (error) {
    return <div className="min-h-screen bg-background text-red-500 flex items-center justify-center">{error}</div>;
  }

  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Market Overview</h1>

      {flag && (
        <div className="p-4 bg-green-800 text-white text-center rounded">
          <p className="text-xl font-bold">Flag: {flag}</p>
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-3">
        {cryptoData.map((crypto) => (
          <Card key={crypto.symbol} className="p-4">
            <div className="flex justify-between items-center">
              <div>
                <p className="text-sm text-muted-foreground">{crypto.name}</p>
                <p className="text-2xl font-bold">${crypto.price.toLocaleString()}</p>
              </div>
              <div className={parseFloat(crypto.change24h) >= 0 ? 'text-green-500' : 'text-red-500'}>
                {parseFloat(crypto.change24h) > 0 ? '+' : ''}{crypto.change24h}%
              </div>
            </div>
            <button
              onClick={() => setSelectedSymbol(crypto.symbol)}
              className="mt-4 text-blue-500 hover:underline"
            >
              View History
            </button>
          </Card>
        ))}
      </div>

      {historyData.length > 0 && selectedCrypto && (
        <Card className="p-6">
          <h2 className="text-xl font-bold mb-4">
            Price History for {selectedCrypto.name} ({selectedCrypto.symbol})
          </h2>
          <div className="flex justify-between mb-4">
            {['24', '7', '30', '365'].map((p) => (
              <button
                key={p}
                className={`mx-1 px-4 py-2 text-sm rounded ${period === parseInt(p) ? 'bg-blue-500 text-white' : 'text-blue-500'}`}
                onClick={() => setPeriod(parseInt(p))}
              >
                {p === '24' ? '24h' : p === '7' ? '1 Week' : p === '30' ? '1 Month' : '1 Year'}
              </button>
            ))}
          </div>
          <div className="h-[400px]">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={historyData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Line type="monotone" dataKey="price" stroke="#f59e0b" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Card>
      )}
    </div>
  );
}