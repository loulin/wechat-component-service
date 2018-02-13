# wechat-component-service

## Basic Usage

```js
const ComponentService = require('wechat-component-service');

const service = new ComponentService({
  appid: '<WECHAT_COMPONENT_APPID>',
  token: '<WECHAT_COMPONENT_TOKEN>',
  appsecret: '<WECHAT_COMPONENT_APPSECRET>',
});

const component = service.getComponent(); // wechat component instance
const api = service.api(authorizerAppid); // wechat-api wrapper
const oauth = service.oauth(authorizerAppid); // wechat-oauth wrapper
const strategy = service.strategy(authorizerAppid); // passport-wechat strategy wrapper
```
