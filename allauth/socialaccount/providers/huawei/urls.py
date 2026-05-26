from allauth.socialaccount.providers.huawei.provider import HuaweiProvider
from allauth.socialaccount.providers.oauth2.urls import default_urlpatterns


urlpatterns = default_urlpatterns(HuaweiProvider)
