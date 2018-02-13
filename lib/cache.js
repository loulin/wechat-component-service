const cacheManager = require('cache-manager');
const redisStore = require('cache-manager-ioredis');

let cache;

module.exports = {
  get(nodes, options) {
    if (cache) return cache;

    if (Array.isArray(nodes)) {
      cache = cacheManager.caching({ store: redisStore, clusterConfig: { nodes, options } });
    } else {
      cache = cacheManager.caching({ store: redisStore, ...nodes });
    }

    return cache;
  },
};
