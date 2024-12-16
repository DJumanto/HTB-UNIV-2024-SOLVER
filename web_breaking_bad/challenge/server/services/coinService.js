import { hsetObject, hgetAllObject, getKeysByPattern } from "../utils/redisUtils.js";

const COINS = [
  {
    symbol: "CLCR",
    name: "Cluster Credit",
    basePrice: 133713,
    totalSupply: 50000000000,
    color: "#FF0000",
  },
  {
    symbol: "BTC",
    name: "Bitcoin",
    basePrice: 90000,
    totalSupply: 21000000000,
    color: "#00FFFF",
  },
  {
    symbol: "ETH",
    name: "Ethereum",
    basePrice: 40000,
    totalSupply: 12000000000,
    color: "#FFFF00",
  },
  {
    symbol: "DOGE",
    name: "Dogecoin",
    basePrice: 0.4,
    totalSupply: 132000000,
    color: "#FFA500",
  },
];

const randomizePrice = (basePrice) => {
  const factor = basePrice * 0.08;
  const randomOffset = Math.random() * factor * 2 - factor;
  return parseFloat((basePrice + randomOffset).toFixed(2));
};

export const initializeCoins = async () => {
  for (const coin of COINS) {
    const price = randomizePrice(coin.basePrice);
    const change24h = (Math.random() * 10 - 5).toFixed(2);

    const coinData = {
      symbol: coin.symbol,
      name: coin.name,
      totalSupply: coin.totalSupply,
      color: coin.color,
      price,
      change24h: parseFloat(change24h),
    };

    await hsetObject(`coin:${coin.symbol}`, coinData);
  }

};

export const getAllCoins = async () => {
  const keys = await getKeysByPattern("coin:*");
  const coins = [];

  for (const key of keys) {
    const coinData = await hgetAllObject(key);

    if (coinData) {
      coins.push({
        symbol: coinData.symbol,
        name: coinData.name,
        totalSupply: parseInt(coinData.totalSupply, 10),
        color: coinData.color,
        price: parseFloat(coinData.price || "0"),
        change24h: parseFloat(coinData.change24h || "0"),
      });
    }
  }

  return coins;
};

export const getSupportedCoins = async () => {
  const coins = await getAllCoins();
  return coins.map((coin) => coin.symbol.toUpperCase());
};

export const getBalancesForUser = async (userId) => {
  const walletKey = `wallet:${userId}`;
  const wallet = await hgetAllObject(walletKey);

  if (!wallet || Object.keys(wallet).length === 0) {
    return COINS.map((coin) => ({
      symbol: coin.symbol,
      name: coin.name,
      availableBalance: 0,
    }));
  }

  return COINS.map((coin) => ({
    symbol: coin.symbol,
    name: coin.name,
    availableBalance: parseFloat(wallet[coin.symbol] || 0),
  }));
};

export const getCoinBySymbol = async (symbol) => {
  const coinData = await hgetAllObject(`coin:${symbol.toUpperCase()}`);
  if (!coinData || Object.keys(coinData).length === 0) return null;

  return {
    symbol: coinData.symbol,
    name: coinData.name,
    totalSupply: parseInt(coinData.totalSupply, 10),
    color: coinData.color,
    price: parseFloat(coinData.price),
    change24h: parseFloat(coinData.change24h),
  };
};

export const getCoinHistory = async (symbol, period = 24) => {
  const coin = await getCoinBySymbol(symbol);
  if (!coin) {
    console.warn(`No coin found for symbol: ${symbol}`);
    return null;
  }

  const price = parseFloat(coin.price);
  const history = Array.from({ length: parseInt(period, 10) }, (_, i) => ({
    time: `${i}:00`,
    price: parseFloat(
      (price + Math.random() * 0.1 * price - 0.05 * price).toFixed(2)
    ),
  }));

  return history;
};

export const getWalletAndMarketShare = async (email) => {
  const walletKey = `wallet:${email}`;
  const wallet = await hgetAllObject(walletKey);

  if (!wallet || Object.keys(wallet).length === 0) {
    console.error("Wallet is empty or missing.");
    return { total: 0, assets: [] };
  }

  const allCoins = await getAllCoins();
  const totalWalletValue = Object.values(wallet).reduce(
    (acc, val) => acc + parseFloat(val),
    0
  );

  const calculateShare = (value, totalValue) => {
    return totalValue > 0 ? ((value / totalValue) * 100).toFixed(2) : "0.00";
  };

  const assets = Object.entries(wallet).map(([symbol, value]) => {
    const coinDetails = allCoins.find(
      (c) => c.symbol.toUpperCase() === symbol.toUpperCase()
    );

    if (!coinDetails) {
      console.warn(`Coin details not found for: ${symbol}`);
      return {
        symbol,
        name: symbol,
        value: parseFloat(value),
        color: "#cccccc",
        share: calculateShare(parseFloat(value), totalWalletValue),
        ownership: "0.00",
      };
    }

    const walletShare = calculateShare(parseFloat(value), totalWalletValue);
    const ownershipPercentage = (
      (parseFloat(value) / coinDetails.totalSupply) *
      100
    ).toFixed(2);

    return {
      symbol: coinDetails.symbol,
      name: coinDetails.name,
      value: parseFloat(value),
      color: coinDetails.color,
      share: walletShare,
      ownership: ownershipPercentage,
    };
  });

  return { total: totalWalletValue, assets };
};

export const createDefaultWallet = async (email) => {
  try {
    const walletKey = `wallet:${email}`;
    const defaultWallet = COINS.reduce((acc, coin) => {
      acc[coin.symbol] = 0;
      return acc;
    }, {});

    await hsetObject(walletKey, defaultWallet);

    return {
      success: true,
      message: "Default wallet created successfully.",
      wallet: defaultWallet,
    };
  } catch (error) {
    console.error("Error creating default wallet:", error);
    return {
      success: false,
      error: "Failed to create default wallet.",
    };
  }
};