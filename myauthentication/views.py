import pyotp
from rest_framework.response import Response
from rest_framework import generics,status
from rest_framework.permissions import AllowAny
from .serializer import  SendPasswordResetEmailSerializer, UserChangePasswordSerializer,UserRegistrationSerializer,UserLoginSerializer,UserPasswordResetSerializer
from rest_framework.views import APIView
from django.contrib.auth import authenticate
# from rest_framework.authtoken.models import Token
# from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from allauth.socialaccount.models import SocialAccount


# Generate Token Manually
def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }


# class UserRegistrationView(generics.CreateAPIView):
#     permission_classes = [AllowAny]
#     serializer_class = UserRegistrationSerializer
class UserRegistrationView(generics.CreateAPIView):
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        self.resp = {}

        # Validate the request data
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        # Check if the user registered using social authentication
        social_account = SocialAccount.objects.filter(user__email=validated_data['email']).first()
        if social_account:
            # User registered using social authentication, return an error
            self.resp['error'] = "User registration not allowed with social authentication."
        else:
            # User registered using custom sign up, continue with the registration logic

            # Create a new user object
            user = User.objects.create_user(
                email=validated_data['email'],
                password=validated_data['password'],
                first_name=validated_data['first_name'],
                last_name=validated_data['last_name'],
            )

            # Generate a token for the new user
            token = get_tokens_for_user(user)

            self.resp['token'] = token
            self.resp['msg'] = "Registration successful"

        if 'error' in self.resp:
            return Response(self.resp, status=status.HTTP_400_BAD_REQUEST)

        return Response(self.resp, status=status.HTTP_201_CREATED)
    

# class UserLoginView(APIView):
    
#     def post(self, request):

#         serializer = UserLoginSerializer(data=request.data)

#         serializer.is_valid(raise_exception=True)        
#         email = serializer.data.get('email')
#         password = serializer.data.get('password')  
#         user = authenticate(request=request, username=email, password=password)

#         if user is not None:
#             token = get_tokens_for_user(user)
#             return Response({'token':token,'msg': 'Login Success'}, status=status.HTTP_200_OK)
#         else:
#             return Response({'error': 'Email or Password is not Valid'}, status=status.HTTP_404_NOT_FOUND)

class UserLoginView(APIView):
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data

        email = validated_data.get('email')
        password = validated_data.get('password')

        # Check if the user registered using social authentication
        social_account = SocialAccount.objects.filter(user__email=email).first()
        if social_account:
            # User registered using social authentication, return an error
            return Response({"error": "Login not allowed with social authentication."}, status=status.HTTP_400_BAD_REQUEST)

        user = authenticate(request=request, username=email, password=password)

        if user:
            # User is authenticated, generate tokens
            token = get_tokens_for_user(user)
            return Response({'token': token, 'msg': 'Login Success'}, status=status.HTTP_200_OK)
        else:
            # Invalid credentials
            return Response({'error': 'Email or Password is not valid'}, status=status.HTTP_404_NOT_FOUND)
        

class UserChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self ,request):
        serializer = UserChangePasswordSerializer(data = request.data,context={'user':request.user})
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)
    

class SendPasswordResetEmailView(APIView):
    
    def post (self,request):

        serializer = SendPasswordResetEmailSerializer(data = request.data)
        serializer.is_valid(raise_exception=True)
        return Response ({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)
        # return Response({'msg': 'Password Reset OTP sent. Please check your email.'}, status=status.HTTP_200_OK)
    

class UserPasswordResetView(APIView):

  def post(self, request,uid,token):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    # serializer = UserPasswordResetSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)
  

class UserLogoutView(APIView):
    
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
         
            return Response({'msg':'Logout Successfully'},status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(str(e),status=status.HTTP_400_BAD_REQUEST)


# class SendPasswordResetEmailView(APIView):
#     def post(self,request):
        
#         serializer = UserPasswordResetotpSerializer(data = request.data)
#         serializer.is_valid(raise_exception=True)
#         return Response({'message': 'OTP has been sent'}, status=status.HTTP_200_OK)

# from django.contrib.auth.tokens import default_token_generator
# class VerifyOTPAPIView(APIView):
#     def post(self, request, format=None):
#         otp = request.data.get('otp')

#         try:
#             user = User.objects.get(password_reset_otp=otp)
#         except User.DoesNotExist:
#             return Response({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)

#         # Generate a token for password reset
#         token = default_token_generator.make_token(user)

#         return Response({'token': token}, status=status.HTTP_200_OK)

# views.py


from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from rest_auth.views import LoginView
from rest_auth.registration.views import SocialLoginView

class GoogleLogin(SocialLoginView):
    adapter_class = GoogleOAuth2Adapter

