from django.urls import reverse
from django.utils.http import urlencode

from allauth.core import context
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.models import (
    SocialAccount,
    SocialLogin,
    SocialToken,
)
from allauth.socialaccount.providers.base import Provider, ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider
from allauth.socialaccount.providers.weixin.views import (
    WeixinMiniProgramAdapter,
    WeixinOfficialAccountAdapter,
    WeixinOpenPlatformAdapter,
)


class WeixinAccount(ProviderAccount):
    def get_avatar_url(self):
        return self.account.extra_data.get("headimgurl")

    def to_str(self):
        return self.account.extra_data.get("nickname", super().to_str())

    def get_unionid(self):
        return self.account.extra_data.get("unionid", None)


class WeixinLogin(SocialLogin):
    def lookup(self):
        super().lookup()

        if self.is_existing:
            return

        unionid = self.account.get_provider_account().get_unionid()

        if unionid is None:
            return

        a = (
            SocialAccount.objects.only("user")
            .filter(
                provider__in=WeixinProvider.subproviders.keys(),
                extra_data__unionid=unionid,
            )
            .first()
        )
        if not a:
            return

        self.connect(context.request, a.user)


class WeixinProvider(Provider):
    id = "weixin"
    uses_apps = True
    account_class = WeixinAccount
    adapter_class: type

    subproviders = {}
    legacy_url = False

    def __init_subclass__(cls, **kwargs):
        assert issubclass(cls, Provider)
        assert cls.provider_id not in cls.subproviders
        cls.subproviders[cls.provider_id] = cls

    def __new__(cls, request, app=None):
        assert app is not None
        cls = cls.subproviders.get(app.provider_id, WeixinOpenPlatformProvider)
        return super().__new__(cls)

    def get_adapter(self):
        return self.adapter_class(self.request, self.app, self)

    def extract_uid(self, data):
        return data["openid"]

    def extract_common_fields(self, data):
        return dict(username=data.get("nickname"), name=data.get("nickname"))

    def sociallogin_from_response(self, request, response):
        login = super().sociallogin_from_response(request, response)
        return WeixinLogin.deserialize(login.serialize())

    def url_path_kwargs(self):
        if self.legacy_url:
            return {}
        else:
            return {"weixin_appid": self.app.client_id}

    def get_login_url(self, request, **kwargs):
        url = reverse(self.id + "_login", kwargs=self.url_path_kwargs())
        if kwargs:
            url = url + "?" + urlencode(kwargs)
        return url

    def get_callback_url(self):
        return reverse(
            self.id + "_callback",
            kwargs=self.url_path_kwargs(),
        )

    def get_oauth2_adapter(self, request):
        return self.get_adapter()


class WeixinOpenPlatformProvider(WeixinProvider, OAuth2Provider):
    provider_id = "open-platform"
    name = "Weixin Open Platform"
    adapter_class = WeixinOpenPlatformAdapter
    supports_redirect = True
    supports_token_authentication = True
    pkce_enabled_default = False

    def get_default_scope(self):
        return ["snsapi_login"]

    def verify_token(self, request, token):
        code = token.get("code")
        if not code:
            raise get_adapter().validation_error("invalid_token")

        adapter = self.get_adapter()
        app = self.app
        client = adapter.get_client(request, app)
        access_token = client.get_access_token(code)
        token = adapter.parse_token(access_token)
        if app.pk:
            token.app = app
        login = adapter.complete_login(request, self.app, token, response=access_token)
        return login


class WeixinOfficialAccountOAuth2Provider(WeixinProvider, OAuth2Provider):
    provider_id = "official-account"
    name = "Weixin Official Account Platform"
    adapter_class = WeixinOfficialAccountAdapter
    supports_redirect = True
    pkce_enabled_default = False

    def get_default_scope(self):
        return ["snsapi_base"]


class WeixinMiniProgramProvider(WeixinProvider, Provider):
    provider_id = "mini-program"
    name = "Weixin Mini Program"
    adapter_class = WeixinMiniProgramAdapter
    supports_token_authentication = True

    def verify_token(self, request, token):
        js_code = token.get("js_code")
        if not js_code:
            raise get_adapter().validation_error("invalid_token")

        adapter = self.get_adapter()
        identity_data = adapter.jscode2session(self.app, js_code)
        session_key = identity_data.pop("session_key")
        token = SocialToken(token=session_key)
        login = self.sociallogin_from_response(request, identity_data)
        login.token = token
        return login

    def extract_session_key(self, data):
        return data["session_key"]


provider_classes = [
    WeixinProvider,
]
