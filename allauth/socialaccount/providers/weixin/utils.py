from django.http import Http404

from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.models import SocialApp
from allauth.socialaccount.providers.weixin.provider import WeixinProvider


def get_app_or_404(request, weixin_appid):
    adapter = get_adapter()
    try:
        return adapter.get_app(
            request, provider=WeixinProvider.id, client_id=weixin_appid
        )
    except SocialApp.DoesNotExist:
        raise Http404(f"no SocialApp found with client_id={weixin_appid}")
