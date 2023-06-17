from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
import pyotp
from rest_framework import serializers
from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from rest_framework.response import Response
import re 
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError

from myauthentication.utils import Util


class UserRegistrationSerializer(serializers.Serializer):
    status = serializers.BooleanField(read_only=True)
    error = serializers.CharField(read_only=True)
    message = serializers.CharField(read_only=True)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = None
        self.resp = {'status' : False}
        self.fields["first_name"] = serializers.CharField(required = True, write_only=True )
        self.fields["last_name"] = serializers.CharField(required = True, write_only=True )
        self.fields["email"] = serializers.EmailField(required=True, write_only=True)
        self.fields["password"] = serializers.CharField(required = True, write_only=True )
        self.fields["password2"] = serializers.CharField(required = True, write_only=True )
    
    def validate(self, attrs):
        password = attrs['password']
        password2 = attrs['password2']
        attrs['valid'] = False
        user_exist = User.objects.filter(email = attrs['email']).exists()

        if user_exist:
            self.resp['error'] = "Email must be Unique."
        elif password != password2:
            self.resp['error'] = "Password fields didn't match."
        elif not any(char.islower() for char in password):
            self.resp['error'] = "Password must contain at least one lowercase letter."
        elif not any(char.isupper() for char in password):
            self.resp['error'] = "Password must contain at least one uppercase letter.."
        elif not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            self.resp['error'] = "Password must contain at least one unique character."
        else:
            attrs['valid'] = True
        return attrs
    
    def create(self, validated_data):
        print("validated_data:", validated_data)
        if validated_data['valid'] == True:
            try:
                with transaction.atomic():
                    print("validated_data:", validated_data)
                  
                    user_obj = User.objects.create(
                        username=validated_data['email'],
                        email=validated_data['email'],
                        first_name=validated_data['first_name'],
                        last_name=validated_data['last_name'],
                    )
                    print("user_obj:", user_obj)
                    user_obj.set_password(validated_data['password'])
                    user_obj.save()
                    self.resp['status'] = True
                    self.resp["message"] = "User Registered successfully"
                    # self.resp["status"] = True
                    print("self.resp : ", self.resp)
            except IntegrityError:
                self.resp['error'] ="User Already Exists, Try Adding other username"
                
        return self.resp


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.CharField(max_length=255, required=True)
    class Meta:

        model = User
        fields = ['email','password']

class UserChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length = 255, style = {'input_type':'password'},write_only = True)
    password = serializers.CharField(max_length = 255, style = {'input_type':'password'},write_only = True)
    password2 = serializers.CharField(max_length = 255, style = {'input_type':'password'},write_only = True)

    class Meta:
        fields = ['password','password2','old_password']
    

    def validate_old_password(self,value):
            user = self.context.get('user')
            if not user.check_password(value):
                raise serializers.ValidationError({"old_password": "Old password is not correct"})
            return value
            


    def validate(self, attrs):
        password = attrs['password']
        password2 = attrs['password2']
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        user.set_password(password)
        user.save()


        return super().validate(attrs)
    

class SendPasswordResetEmailSerializer(serializers.Serializer):

    email = serializers.EmailField(max_length = 255)
    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs['email']
        if User.objects.filter(email = email).exists():
            user = User.objects.get(email = email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print('Encoded UID', uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print('Password Reset Token', token)
            link = 'http://localhost:9000/auth/api/reset-password/'+uid+'/'+token
            print('Password Reset Link', link)
            body = 'Click Following Link to Reset Your Password '+link
            data = {
                'subject':'Reset Password',
                'body':body,
                'to_email':user.email
            }
            Util.send_email(data)
            # base32_otp = pyotp.random_base32()
            # otp = pyotp.totp.TOTP(base32_otp).now()
            # user.otp_secret = otp
            # user.save()
            # print(otp,"=================")
            
            # email_data = {
            #     'subject': 'Password Reset OTP',
            #     'body': f'Your OTP for password reset: {otp}',
            #     'to_email': user.email
            # }
            # Util.send_email(email_data)
            return attrs
        else:

            raise serializers.ValidationError('You are not a Registered User')
    

class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    # otp = serializers.CharField(max_length=6)
    class Meta:
        fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            # otp = attrs['otp']
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("Password and Confirm Password doesn't match")
            try:
                id = smart_str(urlsafe_base64_decode(uid))
                user = User.objects.get(id=id)
            except(User.DoesNotExist,ValueError):
                raise serializers.ValidationError('Invalid user')
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError('Token is not Valid or Expired')
            
            user.set_password(password)
            user.save()
            
            #otp
            # if pyotp.TOTP(user.otp_secret).verify(otp):
            #     user.set_password(password)
            #     user.save()
            # # user.set_password(password)
            # # user.save()
            # else:
            #     raise serializers.ValidationError('otp is not Valid or Expired')
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise serializers.ValidationError('Token is not Valid or Expired')
        
        
        
        
class UserPasswordResetotpSerializer(serializers.Serializer):
        
        email = serializers.EmailField(max_length = 255)
        class Meta:
            fields = ['email']

        def validate(self, attrs):
            email = attrs['email']
            if User.objects.filter(email = email).exists():
                user = User.objects.get(email = email)
                uid = urlsafe_base64_encode(force_bytes(user.id))
                print('Encoded UID', uid)
                token = PasswordResetTokenGenerator().make_token(user)
                print('Password Reset Token', token)
                link = 'http://localhost:9000/auth/api/reset-password/'+uid+'/'+token
                print('Password Reset Link', link)
                body = 'Click Following Link to Reset Your Password '+link
                data = {
                    'subject':'Reset Password',
                    'body':body,
                    'to_email':user.email
                }
                Util.send_email(data)
            
                return attrs
            else:

                raise serializers.ValidationError('You are not a Registered User')