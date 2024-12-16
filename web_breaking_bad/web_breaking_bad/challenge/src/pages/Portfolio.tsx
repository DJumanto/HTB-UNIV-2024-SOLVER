import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Card } from '@/components/ui/card';
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Legend,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';

export default function Portfolio() {
  const [portfolioData, setPortfolioData] = useState([]);
  const [marketShareData, setMarketShareData] = useState([]);
  const [transactionHistory, setTransactionHistory] = useState([]);
  const [totalValue, setTotalValue] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchPortfolioData = async () => {
      try {
        const token = localStorage.getItem('jwt');
        if (!token) {
          setError('No access token found. Please log in.');
          setLoading(false);
          return;
        }

        const [marketShareResponse, transactionResponse] = await Promise.all([
          axios.get('/api/crypto/market-share', {
            headers: { Authorization: `Bearer ${token}` },
          }),
          axios.get('/api/crypto/transactions', {
            headers: { Authorization: `Bearer ${token}` },
          }),
        ]);

        const { total, assets } = marketShareResponse.data;
        const transactions = transactionResponse.data.sort(
          (a, b) => new Date(b.timestamp) - new Date(a.timestamp)
        );

        let portfolioData = assets.map((asset) => ({
          ...asset,
          share: parseFloat(asset.share),
          value: parseFloat(asset.value) || 0,
        }));

        if (
          total === 0 ||
          portfolioData.every((asset) => asset.value === 0 || asset.share === 0)
        ) {
          portfolioData = [
            {
              symbol: 'No Assets',
              share: 100,
              value: 0,
              color: '#cccccc',
            },
          ];
          setTotalValue(0);
        } else {
          setTotalValue(total);
        }

        const marketShareData = assets.map((asset) => ({
          coin: asset.symbol,
          marketShare: parseFloat(asset.ownership) || 0,
          color: asset.color || '#cccccc',
        }));

        setPortfolioData(portfolioData);
        setMarketShareData(marketShareData);
        setTransactionHistory(transactions);
        setLoading(false);
      } catch (err) {
        console.error('Error fetching portfolio data:', err);
        setError('An error occurred while fetching portfolio data.');
        setLoading(false);
      }
    };

    fetchPortfolioData();
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center text-xl bg-background">
        Loading portfolio...
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center text-red-600 text-xl bg-background">
        {error}
      </div>
    );
  }

  return (
    <div className="space-y-6 text-white bg-background p-6">
      <h1 className="text-3xl font-bold">Portfolio</h1>

      <div className="grid gap-6 md:grid-cols-2">
        <Card className="p-6 bg-background">
          <h2 className="text-xl font-bold mb-4">Portfolio Value</h2>
          <p className="text-3xl font-bold">
            ${totalValue.toLocaleString()}
          </p>
        </Card>

        <Card className="p-6 bg-background">
          <h2 className="text-xl font-bold mb-4">Asset Distribution</h2>
          {portfolioData.length === 1 && portfolioData[0].symbol === 'No Assets' && (
            <p className="mb-4 text-gray-300">bish u broke</p>
          )}
          <div className="h-[300px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={portfolioData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="share"
                  nameKey="symbol"
                  labelLine={false}
                  label={({ name }) => (name !== 'No Assets' ? name : '')}
                >
                  {portfolioData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color || '#cccccc'} />
                  ))}
                </Pie>
                <Tooltip
                  formatter={(value, name) =>
                    name === 'No Assets' ? ['$0', name] : [`${value}%`, name]
                  }
                />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Card>

        {/* Market Share */}
        {marketShareData.length > 0 && (
          <Card className="p-6 bg-background">
            <h2 className="text-xl font-bold mb-4">Market Share</h2>
            <div className="h-[300px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={marketShareData}
                  margin={{ top: 20, right: 30, left: 0, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="coin" />
                  <YAxis />
                  <Tooltip formatter={(value, name) => [`${value.toFixed(2)}%`, name]} />
                  <Bar dataKey="marketShare">
                    {marketShareData.map((entry, index) => (
                      <Cell key={`bar-cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            {/* Display a message if all market shares are zero */}
            {marketShareData.every((data) => data.marketShare === 0) && (
              <p className="mt-4 text-gray-300 text-center">
                You currently hold no market share.
              </p>
            )}
          </Card>
        )}

        {/* Transaction History */}
        <Card className="p-6 bg-background">
          <h2 className="text-xl font-bold mb-4">Transaction History</h2>
          <table className="w-full text-left border-collapse">
            <thead>
              <tr>
                <th className="px-4 py-2 border-b border-gray-700">Time</th>
                <th className="px-4 py-2 border-b border-gray-700">Symbol</th>
                <th className="px-4 py-2 border-b border-gray-700">Units</th>
                <th className="px-4 py-2 border-b border-gray-700">Type</th>
              </tr>
            </thead>
            <tbody>
              {transactionHistory.length > 0 ? (
                transactionHistory.map((transaction, index) => (
                  <tr key={index} className="border-b border-gray-700">
                    <td className="px-4 py-2 text-gray-400">
                      {new Date(transaction.timestamp).toLocaleString()}
                    </td>
                    <td className="px-4 py-2 text-gray-300">
                      {transaction.coin}
                    </td>
                    <td className="px-4 py-2 text-green-500">
                      {transaction.amount.toLocaleString()} units
                    </td>
                    <td className="px-4 py-2 text-gray-300">
                      {transaction.type}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={4} className="px-4 py-2 text-gray-400 text-center">
                    No transactions available.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </Card>
      </div>
    </div>
  );
}
