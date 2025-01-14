from dj_rest_auth.registration.views import ResendEmailVerificationView, VerifyEmailView
from dj_rest_auth.views import (
    LogoutView,
    PasswordChangeView,
    PasswordResetConfirmView,
    PasswordResetView,
    LoginView
)
from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path, re_path
from django.views.generic import TemplateView
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

from users.views import GoogleLogin, email_confirm_redirect, password_reset_confirm_redirect

urlpatterns = [
    path("api/products/", include("products.urls", namespace="products")),
    path("admin/", admin.site.urls),
    path("api/user/", include("users.urls", namespace="users")),
    path("api-auth/", include("rest_framework.urls", namespace="rest_framework")),
    path('dj-rest-auth/', include('dj_rest_auth.urls')),
    path('dj-rest-auth/registration/', include('dj_rest_auth.registration.urls')),
    path(
        "resend-email/", ResendEmailVerificationView.as_view(), name="rest_resend_email"
    ),
    path('account-confirm-email/', VerifyEmailView.as_view(),
         name='account_email_verification_sent'),
    path("account-confirm-email/<str:key>/",
         email_confirm_redirect, name="account_confirm_email"),
    path("user/login/google/", GoogleLogin.as_view(), name="google_login"),
    path("password/reset/", PasswordResetView.as_view(),
         name="rest_password_reset"),
    path(
        "password/reset/confirm/<str:uidb64>/<str:token>",
        password_reset_confirm_redirect,
        name="password_reset_confirm",
    ),
    path("password/change/", PasswordChangeView.as_view(),
         name="rest_password_change"),
    path("logout/", LogoutView.as_view(), name="rest_logout"),
]

# Media Assets
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


# Schema URLs
urlpatterns += [
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("", SpectacularSwaggerView.as_view(
        url_name="schema"), name="swagger-ui"),
]
