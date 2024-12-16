import { rpushList, lrangeList, getListLength } from '../utils/redisUtils.js';

export const trackClick = async (ref, url) => {
    const timestamp = new Date().toISOString();
    const clickData = { ref, url, timestamp };
    await rpushList('analytics:clicks', JSON.stringify(clickData));
};

export const getAnalyticsData = async (start = 0, limit = 10) => {
    const clicks = await lrangeList('analytics:clicks', start, start + limit - 1);
    const totalCount = await getListLength('analytics:clicks');
    const data = clicks.map((item) => JSON.parse(item));
    return { totalCount, start, limit, data };
};
