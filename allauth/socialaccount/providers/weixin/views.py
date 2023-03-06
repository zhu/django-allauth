import requests

from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)

from .client import WeixinOAuth2Client
from .provider import WeixinProvider


class WeixinOAuth2Adapter(OAuth2Adapter):
    provider_id = WeixinProvider.id
    access_token_url = "https://api.weixin.qq.com/sns/oauth2/access_token"
    profile_url = "https://api.weixin.qq.com/sns/userinfo"
    client_class = WeixinOAuth2Client

    AUTHORIZE_URL = {
            'mp': 'https://open.weixin.qq.com/connect/oauth2/authorize',
            'op': "https://open.weixin.qq.com/connect/qrconnect",
            }

    @property
    def authorize_url(self):
        app_type_and_scope = self.get_provider().get_app_type_and_scope()
        settings = self.get_provider().get_settings()
        url = settings.get("AUTHORIZE_URL", None)

        if not url and app_type_and_scope:
            url = self.AUTHORIZE_URL.get(app_type_and_scope[0], None)

        if not url:
            url = "https://open.weixin.qq.com/connect/qrconnect"

        return url

    def complete_login(self, request, app, token, **kwargs):
        openid = kwargs.get("response", {}).get("openid")
        resp = requests.get(
            self.profile_url,
            params={"access_token": token.token, "openid": openid},
        )
        resp.raise_for_status()
        extra_data = resp.json()
        nickname = extra_data.get("nickname")
        if nickname:
            extra_data["nickname"] = nickname.encode("raw_unicode_escape").decode(
                "utf-8"
            )
        return self.get_provider().sociallogin_from_response(request, extra_data)


oauth2_login = OAuth2LoginView.adapter_view(WeixinOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(WeixinOAuth2Adapter)
