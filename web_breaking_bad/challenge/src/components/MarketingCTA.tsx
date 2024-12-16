import React, { useState } from 'react';

const MarketingCTA = () => {
  const [isVisible, setIsVisible] = useState(true);

  const handleClick = async () => {
    const ref = 'cta-announcement';
    const redirectUrl = encodeURIComponent('https://www.youtube.com/watch?v=dQw4w9WgXcQ'); // Replace with actual signup link

    try {
      await fetch(`/api/analytics/redirect?ref=${ref}&url=${redirectUrl}`, {
        method: 'GET',
        mode: 'no-cors',
      });

      window.location.href = decodeURIComponent(redirectUrl);
    } catch (error) {
      console.error('Error handling click:', error);
    }
  };

  if (!isVisible) return null;

  return (
    <div className="top-0 left-0 z-50 w-full p-4 bg-green-600 text-white flex justify-between items-center shadow-lg">
      <div className="flex items-center">
        <p className="text-sm font-medium">
          🎉 Join CryptoX now and get <strong>$13.37 for free</strong> to start your trading journey!
        </p>
      </div>
      <div className="flex items-center gap-4">
        <button
          onClick={handleClick}
          className="bg-white text-green-600 px-4 py-2 rounded-lg font-medium hover:bg-gray-200 transition"
        >
          Claim Your $13.37
        </button>
        <button
          onClick={() => setIsVisible(false)}
          className="text-sm underline hover:text-gray-200 transition"
        >
          Dismiss
        </button>
      </div>
    </div>
  );
};

export default MarketingCTA;