import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import axios from "axios";

interface Friend {
  email: string;
}

interface FriendRequest {
  from: string;
}

interface FriendsContextType {
  friends: Friend[];
  friendRequests: FriendRequest[];
  setFriends: React.Dispatch<React.SetStateAction<Friend[]>>;
  setFriendRequests: React.Dispatch<React.SetStateAction<FriendRequest[]>>;
  refreshData: () => Promise<void>;
}

const FriendsContext = createContext<FriendsContextType | undefined>(undefined);

export const FriendsProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [friends, setFriends] = useState<Friend[]>([]);
  const [friendRequests, setFriendRequests] = useState<FriendRequest[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fallbackErrorMessage = "Failed to fetch friends or friend requests.";

  const fetchFriendsAndRequests = useCallback(async () => {
    const token = localStorage.getItem("jwt");

    if (!token) {
      console.warn("No token found. Skipping data fetch.");
      setLoading(false);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const [friendsRes, requestsRes] = await Promise.all([
        axios.get<{ friends: string[] }>("/api/users/friends", {
          headers: { Authorization: `Bearer ${token}` },
        }),
        axios.get<{ requests: { from: string }[] }>("/api/users/friend-requests", {
          headers: { Authorization: `Bearer ${token}` },
        }),
      ]);

      const transformedFriends = friendsRes.data.friends.map((email) => ({ email }));
      setFriends(transformedFriends);
      setFriendRequests(requestsRes.data.requests || []);
    } catch (err: any) {
      console.error("Error fetching friends/requests:", err);

      if (err.response?.status === 401) {
        console.error("Invalid token detected. Clearing local state.");
        localStorage.removeItem("jwt");
      }

      setError(err.response?.data?.error || fallbackErrorMessage);
    } finally {
      setLoading(false);
    }
  }, []);

  const refreshData = useCallback(async () => {
    await fetchFriendsAndRequests();
  }, [fetchFriendsAndRequests]);

  useEffect(() => {
    fetchFriendsAndRequests();
  }, [fetchFriendsAndRequests]);

  return (
    <FriendsContext.Provider
      value={{
        friends,
        friendRequests,
        setFriends,
        setFriendRequests,
        refreshData,
      }}
    >
      {loading ? (
        <div className="min-h-screen flex items-center justify-center bg-gray-100 text-gray-700">
          <p>Loading friends data...</p>
        </div>
      ) : error ? (
        <div className="min-h-screen flex items-center justify-center bg-gray-100 text-red-500">
          <p>{error}</p>
        </div>
      ) : (
        children
      )}
    </FriendsContext.Provider>
  );
};

export const useFriends = () => {
  const context = useContext(FriendsContext);
  if (!context) {
    throw new Error("useFriends must be used within a FriendsProvider");
  }
  return context;
};