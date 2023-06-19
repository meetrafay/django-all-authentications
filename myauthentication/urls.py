from django.urls import include, path
from rest_framework_simplejwt.views import (TokenObtainPairView,TokenRefreshView,TokenVerifyView)
from myauthentication.views import SendPasswordResetEmailView, UserLoginView, UserLogoutView, UserPasswordResetView, UserRegistrationView,UserChangePasswordView

urlpatterns = [
    path('register/',UserRegistrationView.as_view(),name = "User_Registration"),
    path('login/',UserLoginView.as_view(),name="login_user"),
    # path('login/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('change-password/',UserChangePasswordView.as_view(),name = "change_password"),
    path('reset-password-email/',SendPasswordResetEmailView.as_view(),name = "Send_PasswordReset_Email"),
    path('reset-password/<uid>/<token>/',UserPasswordResetView.as_view(),name = "Send_PasswordReset"),
    # path('reset-password-otp/',SendPasswordResetEmailView.as_view(),name = "Send_PasswordReset"),
    # path('reset-password-otp-verify/',VerifyOTPAPIView.as_view(),name = "verifyotpPasswordReset"),
    
    
    
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/',TokenVerifyView.as_view(),name = "verify token"),
    path('logout/',UserLogoutView.as_view(),name = "logout_user"),
]