from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider
from allauth.socialaccount import app_settings
from allauth.utils import get_request_param
from django.db.models import JSONField
from django.db.models.functions import Cast
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import PermissionDenied


class WeixinAccount(ProviderAccount):
    def get_avatar_url(self):
        return self.account.extra_data.get("headimgurl")

    def to_str(self):
        return self.account.extra_data.get(
            "nickname", super(WeixinAccount, self).to_str()
        )


class WeixinProvider(OAuth2Provider):
    id = "weixin"
    name = "Weixin"
    account_class = WeixinAccount

    def extract_uid(self, data):
        return data["openid"]

    def get_default_scope(self):
        return ["snsapi_login"]

    def extract_common_fields(self, data):
        return dict(username=data.get("nickname"), name=data.get("nickname"))

    def get_app(self, request):
        # NOTE: Avoid loading models at top due to registry boot...
        from allauth.socialaccount.models import SocialApp

        apps = self.get_apps()

        state = getattr(request, 'state', {})
        app_id = state.get('app_id') or request.GET.get('app_id')

        if app_id:
            for app in apps:
                if app.client_id == app_id:
                    return app
            else:
                raise SocialApp.DoesNotExist
        elif len(apps) > 1:
            raise SocialApp.MultipleObjectsReturned
        else:
            return apps[0]

    def get_apps(self):
        # NOTE: Avoid loading models at top due to registry boot...
        from allauth.socialaccount.models import SocialApp

        settings = app_settings.PROVIDERS.get(self.id, {})
        configs = settings.get('APPS', [])
        config = settings.get('APP')
        if config:
            configs.append('config')

        apps = []
        if configs:
            for config in configs:
                app = SocialApp(provider=self.id)
                for field in ["client_id", "secret", "key", "certificate_key"]:
                    setattr(app, field, config.get(field))
                apps.append(app)
        else:
            site = get_current_site(self.request)
            apps = SocialApp.objects.filter(
                    provider=self.id, sites__id=site.id
                    )
        return apps

    @classmethod
    def get_social_login(kls):
        # NOTE: Avoid loading models at top due to registry boot...
        from allauth.socialaccount.models import SocialAccount
        SocialLogin = super().get_social_login()

        class WeixinSocialLogin(SocialLogin):
            def lookup(self):
                """ lookup unionid if openid not found
                """
                super().lookup()

                if self.is_existing:
                    return

                unionid = self.account.extra_data.get('unionid')
                if not unionid:
                    return

                try:
                    a = SocialAccount.objects.alias(
                            extra_json=Cast('extra_data', JSONField())
                            ).get(
                        provider=self.account.provider,
                        extra_json__unionid=unionid
                    )

                    # Update account
                    self.account.user = a.user
                    self.user = self.account.user
                    self.account.save()
                    # Update token
                    if app_settings.STORE_TOKENS and self.token and self.token.app.pk:
                        assert not self.token.pk
                        self.token.account = self.account
                        self.token.save()
                except SocialAccount.DoesNotExist:
                    pass

            @classmethod
            def state_from_request(cls, request):
                state = super().state_from_request(request)
                app_id = get_request_param(request, "app_id", None)
                if app_id:
                    state['app_id'] = app_id
                return state

        return WeixinSocialLogin


provider_classes = [WeixinProvider]
