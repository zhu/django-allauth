Weixin
------

The Weixin OAuth2 documentation:

    https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html

    https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Authorized_Interface_Calling_UnionID.html

    https://developers.weixin.qq.com/doc/oplatform/Mobile_App/WeChat_Login/Development_Guide.html


The Weixin Mini Program documentation:

    https://developers.weixin.qq.com/miniprogram/dev/framework/open-ability/login.html


This provider provides access to multiple Weixin authentication subproviders.
You configure these subproviders by adding apps to the
configuration of the overall Weixin provider. Each app represents a
standalone Weixin provider:

.. code-block:: python

    SOCIALACCOUNT_PROVIDERS = {
        'weixin': {
            'APPS': [
                {
                    'provider_id': 'open-platform',
                    'client_id': 'weixin-appid',
                    'secret': 'your-secret',
                    'settings': {
                        # 'authorize_url': ''
                    }
                },
                {
                    'provider_id': 'official-account',
                    'client_id': 'weixin-appid',
                    'secret': 'your-secret',
                    'settings': {
                        'scope': ['snsapi_userinfo'],
                    }
                },
                {
                    'provider_id': 'mini-program',
                    'client_id': 'weixin-appid',
                    'secret': 'your-secret',
                },
                {
                    'provider_id': 'mini-program:yet-another',
                    'client_id': 'another-weixin-appid',
                    'secret': 'your-secret-for-another-app',
                },
            ],
            # 'SCOPE': [],  #  override all default scope
            # 'AUTHORIZE_URL': ''  # override all default authorize url
        }
    }

Weixin supports two kinds of oauth2 authorization, one for open platform and
one for media platform, use provider_id ``open-platform`` for open platform,
use provider_id ``official-account`` for media platform.
If you have more than one app for the same subprovider, use
``{{provider_id}}:{{unique_app_ident}}`` as provider_id.

You can optionally specify additional scope to use. If no ``scope`` value is
set, will use ``snsapi_login`` by default(for Open Platform Account, need
registration), ``snsapi_base`` for media platform. Other ``scope`` option for
media platform: ``snsapi_userinfo``.

Weixin mini program authentication is provided by provider_id ``mini-program``.

This provider supports Weixin's unionid merchant to lookup user. You should
bind all Weixin apps to the same Open Platform Account. Note: Weixin does *not*
provide unionid when scope ``snsapi_base``.

This provider has these endpoints for oauth2 login:

- ``/accounts/weixin/{weixin-appid}/login/``
- ``/accounts/weixin/{weixin-appid}/callback/``

Mobile applications (Open Platform) is exclusively supported via the Headless API's "provider
token" flow. Pass your authorization code to that endpoint as a ``code``.

Mini Program is exclusively supported via the Headless API's "provider
token" flow. Pass your authorization code to that endpoint as a ``js_code``.

Legacy:
    ``/accounts/weixin/login/`` and ``/accounts/weixin/callback/`` are provided
    for compatible purpose. They are worked when there is only one available
    weixin app.
    ``provider_id`` other than ``open-platform``, ``official-account``,
    ``mini-program`` will fallback to ``open-platform``.
    You should migrate old app.provider_id and account.provider to new provider_id
    before add another app.
