const Redlock = require('redlock');
const Redis = require('ioredis');

let lock;

module.exports = {
  get(clients, options) {
    if (lock) return lock;

    if (Array.isArray(clients)) {
      lock = new Redlock(clients.map(client => new Redis(client)), options);
    } else {
      lock = new Redlock([new Redis(clients)], options);
    }

    return lock;
  },
};
