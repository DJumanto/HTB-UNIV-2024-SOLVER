import React, { useState } from 'react';
import { useFriends } from '@/context/FriendsContext';
import { Card } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { UserPlus, Check, X, Users } from 'lucide-react';
import axios from 'axios';

export default function Friends() {
  const { friends, friendRequests, setFriends, setFriendRequests } = useFriends();
  const [addFriendEmail, setAddFriendEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleAddFriend = async () => {
    setLoading(true);
    try {
      const token = localStorage.getItem('jwt');
      const response = await axios.post(
        '/api/users/friend-request',
        { to: addFriendEmail },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      if (response.data.success) {
        setSuccess(`Friend request sent to ${addFriendEmail}`);
        setAddFriendEmail('');
        setError('');
      } else {
        setError(response.data.message || 'Failed to send friend request');
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to send friend request');
      setAddFriendEmail('');
      setSuccess('');
    } finally {
      setLoading(false);
    }
  };

  const handleAction = async (email: string, action: 'accept' | 'decline') => {
    setLoading(true);
    try {
      const token = localStorage.getItem('jwt');
      const url = `/api/users/${action}-friend`;

      await axios.post(
        url,
        { from: email },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      if (action === 'accept') {
        setFriends((prev) => [...prev, { email }]);
        setSuccess(`You are now friends with ${email}`);
      } else {
        setSuccess(`Friend request from ${email} declined`);
      }

      setFriendRequests((prev) => prev.filter((req) => req[0] !== email));
      setError('');
    } catch (err) {
      setError(`Failed to ${action} friend request`);
      setSuccess('');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold">Friends</h1>
        <div className="flex items-center space-x-2">
          <Users className="h-5 w-5" />
          <span className="font-medium">{friends.length} Friends</span>
        </div>
      </div>

      <Card className="p-6">
        <h2 className="text-xl font-semibold mb-4">Add New Friend</h2>
        <div className="flex gap-4">
          <Input
            type="email"
            placeholder="Enter friend's email"
            value={addFriendEmail}
            onChange={(e) => setAddFriendEmail(e.target.value)}
            className="flex-1"
          />
          <Button
            onClick={handleAddFriend}
            disabled={loading || !addFriendEmail}
            className="flex items-center gap-2 hover:bg-blue-500 transition"
          >
            <UserPlus className="h-4 w-4" />
            Add Friend
          </Button>
        </div>
      </Card>

      {error && (
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded transition">
          {error}
        </div>
      )}
      {success && (
        <div className="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded transition">
          {success}
        </div>
      )}

      {friendRequests.length > 0 && (
        <Card className="p-6">
          <h2 className="text-xl font-semibold mb-4">Friend Requests</h2>
          <div className="space-y-4">
            {friendRequests.map(([email, status], index) => (
              <div
                key={`friend-request-${index}`}
                className="flex items-center justify-between p-4 bg-secondary rounded-lg"
              >
                <span className="font-medium">{email}</span>
                <div className="flex gap-2">
                  <Button
                    onClick={() => handleAction(email, 'accept')}
                    variant="default"
                    size="sm"
                    className="flex items-center gap-1 hover:bg-green-500 transition"
                    disabled={loading}
                  >
                    <Check className="h-4 w-4" />
                    Accept
                  </Button>
                  <Button
                    onClick={() => handleAction(email, 'decline')}
                    variant="destructive"
                    size="sm"
                    className="flex items-center gap-1 hover:bg-red-500 transition"
                    disabled={loading}
                  >
                    <X className="h-4 w-4" />
                    Decline
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card className="p-6">
        <h2 className="text-xl font-semibold mb-4">Your Friends</h2>
        {friends.length > 0 ? (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            {friends.map((friend) => (
              <div
                key={`friend-${friend.email}`}
                className="p-4 bg-secondary rounded-lg flex items-center justify-between"
              >
                <span className="font-medium">{friend.email}</span>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-muted-foreground text-center py-8">
            No friends added yet. Start by sending some friend requests!
          </p>
        )}
      </Card>
    </div>
  );
}