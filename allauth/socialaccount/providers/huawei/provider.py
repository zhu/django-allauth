from django.http import HttpRequest

from allauth.socialaccount.providers.openid_connect.provider import (
    OpenIDConnectProvider,
    OpenIDConnectProviderAccount,
)

from .views import HuaweiAdapter


class HuaweiProviderAccount(OpenIDConnectProviderAccount):
    pass


class HuaweiProvider(OpenIDConnectProvider):
    id = "huawei"
    name = "Huawei"
    account_class = HuaweiProviderAccount
    oauth2_adapter_class = HuaweiAdapter
    default_server_url = "https://oauth-login.cloud.huawei.com/"

    @property
    def server_url(self):
        url = self.app.settings.get("server_url", self.default_server_url)
        return self.wk_server_url(url)

    def get_login_url(self, request: HttpRequest, **kwargs):
        return super(OpenIDConnectProvider, self).get_login_url(request, **kwargs)

    def get_callback_url(self):
        return super(OpenIDConnectProvider, self).get_callback_url()

    def extract_uid(self, data):
        if id_token := data.get("id_token"):
            return id_token["sub"]
        else:
            return data["unionId"]


provider_classes = [HuaweiProvider]
