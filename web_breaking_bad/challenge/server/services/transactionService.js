import { hgetAllObject, hsetObject, rpushList, lrangeList } from '../utils/redisUtils.js';

export const transactionByEmail = async (to, from, amount, coin) => {
    try {
      const senderWalletKey = `wallet:${from}`;
      const receiverWalletKey = `wallet:${to}`;
      const senderTransactionKey = `transactions:${from}`;
      const receiverTransactionKey = `transactions:${to}`;
  
      const senderWallet = await hgetAllObject(senderWalletKey);
      const receiverWallet = await hgetAllObject(receiverWalletKey);
  
      if (!senderWallet || !receiverWallet) {
        throw new Error(`Wallet not found for sender (${from}) or receiver (${to})`);
      }
  
      const senderBalance = parseFloat(senderWallet[coin] || 0);
  
      if (senderBalance < amount) {
        return {
          status: 400,
          error: `Insufficient ${coin} balance. Available: ${senderBalance}, Required: ${amount}`,
        };
      }
  
      const updatedSenderBalance = senderBalance - amount;
      const updatedReceiverBalance = parseFloat(receiverWallet[coin] || 0) + amount;
  
      await hsetObject(senderWalletKey, { [coin]: updatedSenderBalance });
      await hsetObject(receiverWalletKey, { [coin]: updatedReceiverBalance });
  
      const transactionRecord = {
        type: 'transfer',
        from,
        to,
        coin,
        amount,
        timestamp: new Date().toISOString(),
      };
  
      await rpushList(senderTransactionKey, JSON.stringify({ ...transactionRecord, direction: 'out' }));
      await rpushList(receiverTransactionKey, JSON.stringify({ ...transactionRecord, direction: 'in' }));
  
      return {
        success: true,
        message: "Transaction completed successfully.",
        transaction: transactionRecord,
      };
    } catch (error) {
      console.error("Error during transaction:", error);
      return { status: 500, error: "Transaction failed." };
    }
  };

export const getTransactions = async (email) => {
    const transactionsKey = `transactions:${email}`;
    const transactions = await lrangeList(transactionsKey, 0, -1);

    return transactions.map((transaction) => JSON.parse(transaction));
};