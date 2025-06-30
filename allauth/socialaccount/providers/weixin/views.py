import functools
import logging

from django.http import Http404

from allauth.account.internal.decorators import login_not_required
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.providers.oauth2.views import (
    OAuth2Adapter,
    OAuth2CallbackView,
    OAuth2LoginView,
)
from allauth.utils import build_absolute_uri

from .client import WeixinOAuth2Client


logger = logging.getLogger(__name__)


class WeixinOAuth2Adapter(OAuth2Adapter):
    """adapter for Weixin Open Platform"""

    access_token_url = "https://api.weixin.qq.com/sns/oauth2/access_token"  # nosec
    profile_url = "https://api.weixin.qq.com/sns/userinfo"
    client_class = WeixinOAuth2Client
    provider_id = "weixin"

    default_authorize_url: str

    def __init__(self, request, app=None, provider=None):
        self.app = app
        self.provider = provider
        super().__init__(request)

    @property
    def authorize_url(self):
        url = self.app.settings.get("authorize_url")
        if url is None:
            settings = self.get_provider().get_settings()
            url = settings.get("AUTHORIZE_URL", self.default_authorize_url)
        return url

    def get_provider(self):
        if not self.provider:
            self.provider = super().get_provider()
            self.provider.legacy_url = True
        return self.provider

    def get_callback_url(self, request, app):
        callback_url = self.get_provider().get_callback_url()
        protocol = self.redirect_uri_protocol
        return build_absolute_uri(request, callback_url, protocol)

    def get_userinfo(self, access_token, openid):
        resp = (
            get_adapter()
            .get_requests_session()
            .get(
                self.profile_url,
                params={"access_token": access_token, "openid": openid},
            )
        )
        resp.raise_for_status()
        # XXX: Weixin return response header 'content-type'='text/plain'.
        #      So `requests` guesses the encoding is "ISO-8859-1", which is wrong.
        resp.encoding = "utf-8"
        return resp.json()

    def complete_login(self, request, app, token, **kwargs):
        response = kwargs["response"]
        openid = response["openid"]
        scope = response["scope"].split(",")
        extra_data = {"openid": openid}
        unionid = response.get("unionid")
        if unionid:
            extra_data["unionid"] = unionid
        if {"snsapi_login", "snsapi_userinfo"} & set(scope):
            extra_data.update(self.get_userinfo(token.token, openid))
        nickname = extra_data.get("nickname")
        if nickname:
            extra_data["nickname"] = nickname
        return self.get_provider().sociallogin_from_response(request, extra_data)

    @property
    def login_view(self):
        return OAuth2LoginView.adapter_view(self)

    @property
    def callback_view(self):
        return OAuth2CallbackView.adapter_view(self)


class WeixinOpenPlatformAdapter(WeixinOAuth2Adapter):
    default_authorize_url = "https://open.weixin.qq.com/connect/qrconnect"


class WeixinOfficialAccountAdapter(WeixinOAuth2Adapter):
    """adapter for Weixin Official Account Platform"""

    default_authorize_url = "https://open.weixin.qq.com/connect/oauth2/authorize"


class WeixinMiniProgramAdapter:
    jscode2session_url = "https://api.weixin.qq.com/sns/jscode2session"

    def __init__(self, request, app, provider):
        self.request = request
        self.app = app
        self.provider = provider
        super().__init__()

    def get_provider(self):
        return self.provider

    def jscode2session(self, app, js_code):
        resp = (
            get_adapter()
            .get_requests_session()
            .get(
                self.jscode2session_url,
                params={
                    "appid": self.app.client_id,
                    "secret": app.secret,
                    "js_code": js_code,
                    "grant_type": "authorization_code",
                },
            )
        )
        resp.raise_for_status()
        data = resp.json()
        errcode = data.get("errcode")
        if not errcode:
            return data
        elif errcode == 40029:
            raise get_adapter().validation_error("invalid_token")
        else:
            logger.error(
                f"Weixin jscode2session error, {errcode}: {data.get('errmsg')}"
            )
            raise get_adapter().validation_error("invalid_token")


def weixin_view(view_func):
    def inner(view):
        @login_not_required
        @functools.wraps(view)
        def wrapper(request, weixin_appid):
            from .utils import get_app_or_404

            app = get_app_or_404(request, weixin_appid)
            provider = app.get_provider(request)
            adapter = provider.get_adapter()
            if isinstance(view_func, str) and not getattr(provider, view_func):
                raise Http404("SocialApp does not support this action")
            return view(adapter, request)

        return wrapper

    if callable(view_func):
        return inner(view_func)
    return inner


@weixin_view("supports_redirect")
def login(adapter, request):
    return adapter.login_view(request)


@weixin_view("supports_redirect")
def callback(adapter, request):
    return adapter.callback_view(request)


oauth2_login = OAuth2LoginView.adapter_view(WeixinOAuth2Adapter)
oauth2_callback = OAuth2CallbackView.adapter_view(WeixinOAuth2Adapter)
