import { getBalancesForUser } from '../services/coinService.js';
import fs from 'fs/promises';

const FINANCIAL_CONTROLLER_EMAIL = "financial-controller@frontier-board.htb";

/**
 * Checks if the financial controller's CLCR wallet is drained
 * If drained, returns the flag.
 */
export const checkFinancialControllerDrained = async () => {
    const balances = await getBalancesForUser(FINANCIAL_CONTROLLER_EMAIL);
    const clcrBalance = balances.find((coin) => coin.symbol === 'CLCR');

    if (!clcrBalance || clcrBalance.availableBalance <= 0) {
        const flag = (await fs.readFile('/flag.txt', 'utf-8')).trim();
        return { drained: true, flag };
    }

    return { drained: false };
};

