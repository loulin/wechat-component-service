const util = require('util');
const WechatComponent = require('wechat-component');
const API = require('wechat-api');
const OAuth = require('wechat-oauth');
const WechatStrategy = require('passport-wechat');
const debug = require('debug')('wechat-component-service');
const cache = require('./lib/cache');
const redlock = require('./lib/redlock');

const COMPONENT_TICKET_TTL = 600 + 10;
const COMPONENT_TOKEN_TTL = 7200 - 10;
const AUTHORIZER_INFO_TTL = 3600 * 24 * 30;
const AUTHORIZER_TOKEN_TTL = 7200 - 10;

// The Official Platform’s back-end will continue to maintain the usability of
// both old and new access_tokens for a period of 5 minutes

function mapToken(authorizationInfo) {
  return {
    accessToken: authorizationInfo.authorizer_access_token,
    refreshToken: authorizationInfo.authorizer_refresh_token,
    expireTime: new Date().getTime() + ((authorizationInfo.expires_in - 10) * 1000),
  };
}

class ComponentService {
  constructor(config, { client, cacheOptions, redlockOptions } = {}) {
    if (!config.appid || !config.token || !config.appsecret) {
      throw new Error('missing requried parameters: {appid, token, appsecret}');
    }

    this.config = config;
    this.apiMap = {};
    this.oAuthMap = {};
    this.strategyMap = {};
    this.cache = cache.get(client, cacheOptions);
    this.redlock = redlock.get(client, redlockOptions);
  }

  getComponent() {
    if (this.component) return this.component;

    const { appid } = this.config;
    const cacheKey = `wechat:component:${appid}:ticket`;
    const cacheTokenKey = `wechat:component:${appid}:token`;
    const component = new WechatComponent({
      getComponentTicketAsync: async () => this.cache.get(cacheKey),
      getTokenAsync: async () => this.cache.get(cacheTokenKey),
      saveTokenAsync: async token => this.cache.set(
        cacheTokenKey,
        token,
        { ttl: COMPONENT_TOKEN_TTL },
      ),
      ...this.config,
    });

    const getAccessToken = component.getAccessToken.bind(component);

    component.getAccessToken = async () => {
      const lockKey = `wechat:component:${appid}:lock`;
      const lock = await this.redlock.lock(lockKey, 1000); // maximum locked time
      const token = await this.cache.wrap(cacheTokenKey, async () => {
        debug(`component(appid: ${appid}) get new access token from wechat server`);

        return getAccessToken();
      }, { ttl: COMPONENT_TOKEN_TTL });

      await lock.unlock();

      return token;
    };

    this.component = component;

    return component;
  }

  async saveTicket(appid, ticket) {
    const cacheKey = `wechat:component:${appid}:ticket`;

    this.ticket = ticket;
    return this.cache.set(cacheKey, ticket, { ttl: COMPONENT_TICKET_TTL });
  }

  async auth(code) {
    const component = this.getComponent();
    const auth = await component.queryAuth(code);
    const authorizerAppid = auth.authorization_info.authorizer_appid;

    // 在授权的公众号或小程序具备API权限时，才会有token
    if (auth.authorization_info.authorizer_access_token) {
      const authorizerTokenKey = `wechat:${authorizerAppid}:token`;
      const token = mapToken(auth.authorization_info);

      await this.cache.set(authorizerTokenKey, token, { ttl: AUTHORIZER_TOKEN_TTL });
    }

    return auth;
  }

  async getAuthorizerToken(authorizerAppid, _refreshToken) {
    const authorizerTokenKey = `wechat:${authorizerAppid}:token`;
    let refreshToken = _refreshToken;
    let token = await this.cache.get(authorizerTokenKey);

    if (token) return token;

    const component = this.getComponent();

    if (!refreshToken) {
      const authorizerCacheKey = `wechat:${authorizerAppid}:authorizer`;
      const authorizer = await this.cache.wrap(
        authorizerCacheKey,
        async () => component.getAuthorizerInfo(authorizerAppid), { ttl: AUTHORIZER_INFO_TTL },
      );

      debug(`wechat(appid: ${authorizerAppid}) get refreshToken from authorizer info`);
      refreshToken = authorizer.authorization_info.authorizer_refresh_token;
    }

    // 在授权的公众号或小程序具备API权限时，才会有token
    if (!refreshToken) return null;

    const lockKey = `wechat:${authorizerAppid}:lock`;
    const lock = await this.redlock.lock(lockKey, 1000); // maximum locked time

    token = await this.cache.wrap(authorizerTokenKey, async () => {
      const authorizationInfo = await component.getAuthorizerToken(authorizerAppid, refreshToken);

      debug(`wechat(appid: ${authorizerAppid}) get new authorizer token from wechat server`);
      return mapToken(authorizationInfo);
    }, { ttl: AUTHORIZER_TOKEN_TTL });

    await lock.unlock();

    return token;
  }

  async getAuthorizerInfo(authorizerAppid) {
    const component = this.getComponent();
    const authorizerCacheKey = `wechat:${authorizerAppid}:authorizer`;
    const authorizer = await this.cache.wrap(
      authorizerCacheKey,
      async () => component.getAuthorizerInfo(authorizerAppid), { ttl: AUTHORIZER_INFO_TTL },
    );

    return authorizer;
  }

  api(authorizerAppid) {
    if (this.apiMap[authorizerAppid]) return this.apiMap[authorizerAppid];

    const api = new API(authorizerAppid);

    api.getAccessToken = async (callback) => {
      try {
        api.getTokenAsync = util.promisify(api.getToken);
        api.saveTokenAsync = util.promisify(api.saveToken);

        const refresh = await api.getTokenAsync();
        const refreshToken = refresh && refresh.refreshToken;
        const token = await this.getAuthorizerToken(authorizerAppid, refreshToken);

        await api.saveTokenAsync(token);

        callback(null, token);
      } catch (e) {
        callback(e);
      }
    };

    this.apiMap[authorizerAppid] = api;

    return api;
  }

  oauth(authorizerAppid) {
    if (this.oAuthMap[authorizerAppid]) return this.oAuthMap[authorizerAppid];

    const oauth = new OAuth(authorizerAppid);
    const component = this.getComponent();

    oauth.getAccessToken = async (code, callback) => {
      const token = await component.getOAuthAccessToken(authorizerAppid, code);

      oauth.saveToken(token.openid, token, err => callback(err, { data: token }));
    };

    oauth.refreshAccessToken = async (refreshToken, callback) => {
      const token = await component.refreshOAuthAccessToken(authorizerAppid, refreshToken);

      oauth.saveToken(token.openid, token, err => callback(err, { data: token }));
    };

    oauth.getAuthorizeURL = (redirect, state, scope) => component
      .getOAuthAuthorizeURL(authorizerAppid, redirect, scope, state);

    this.oAuthMap[authorizerAppid] = oauth;

    return oauth;
  }

  strategy(opts, verify) {
    let authorizerAppid;
    let options;

    if (typeof opts === 'string') {
      authorizerAppid = opts;
      options = {};
    } else {
      authorizerAppid = opts.appID;
      options = opts;
    }

    if (this.strategyMap[authorizerAppid]) return this.strategyMap[authorizerAppid];

    const strategy = new WechatStrategy({
      name: authorizerAppid,
      appID: authorizerAppid,
      appSecret: '_',
      client: 'wechat',
      scope: 'snsapi_userinfo', // 'snsapi_base'
      ...options,
    }, verify || ((accessToken, refreshToken, profile, expiresIn, done) => done(null, profile)));

    strategy._oauth = this.oauth(authorizerAppid); // eslint-disable-line no-underscore-dangle

    this.strategyMap[authorizerAppid] = strategy;

    return strategy;
  }
}

module.exports = ComponentService;
