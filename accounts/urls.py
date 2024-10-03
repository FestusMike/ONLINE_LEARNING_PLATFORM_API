from django.urls import path
from .views import (

    StudentRegistrationAPIView,
    ResendOTPAPIView,
    OTPVerificationAPIView,
    TutorRegistrationAPIView, PasswordSetUpAPIView, UserLoginAPIView, UserLogoutAPIView, PasswordResetOTPAPIView,
    ForgottenPasswordResetAPIView, DeliberatePasswordResetAPIView, UserProfileUpdateAPIView

    )
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path("student-registration", StudentRegistrationAPIView.as_view(), name="student-registration"),
    path("tutor-registration", TutorRegistrationAPIView.as_view(), name="tutor-registration"),
    path("otp-resend", ResendOTPAPIView.as_view(), name="otp-resend"),
    path("otp-verification", OTPVerificationAPIView.as_view(), name="otp-verification"),
    path("password-setup", PasswordSetUpAPIView.as_view(), name="password-setup"),
    path("user-login", UserLoginAPIView.as_view(), name="user-login"),
    path("user-logout", UserLogoutAPIView.as_view(), name="user-logout"),
    path("password-reset-otp", PasswordResetOTPAPIView.as_view(), name="password-reset-otp"),
    path("deliberate-password-reset", DeliberatePasswordResetAPIView.as_view(), name="deliberate-password-reset"),
    path("forgotten-password-reset", ForgottenPasswordResetAPIView.as_view(), name="forgotten-password-reset"),
    path("token/refresh", TokenRefreshView.as_view(), name="token_pair") ,
    path("profile-update", UserProfileUpdateAPIView.as_view(), name="profile-update")
]

