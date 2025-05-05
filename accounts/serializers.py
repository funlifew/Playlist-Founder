from rest_framework import serializers, status
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import check_password
from django.utils.encoding import force_str, force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed
from utils.password_service import PasswordService


User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    """
    Serializer for User model
    """
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'is_verified', 'is_active',
                'role', 'is_2fa_enabled', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at', 'is_verified']

class RegisterSerializer(serializers.ModelSerializer):
    """This is a serializer for registration"""
    password = serializers.CharField(write_only=True, required=True, style={'input_type': "password"})
    # Confirmation password
    password2 = serializers.CharField(write_only=True, required=True, style={'input_type': "password"})
    
    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password2']
        extra_kwargs = {
            'email': {'required': True},
            'username': {'required': True},
        }
    
    def validate(self, attrs):
        """Validate that passwords like each other"""
        password, password2 = [attrs['password'], attrs['password2']]
        username, email = [attrs['username'], attrs['email']]
        if password != password2:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        # check from password services
        is_valid, errors = PasswordService.validate(
            password,
            username=username,
            email=email
        )
        
        if not is_valid:
            raise serializers.ValidationError({"password": errors})
        
        # Check for PWNED password
        if PasswordService.is_password_pwned(password):
            raise serializers.ValidationError({"password": ["Password is leaked in security breaches, please choose a more secure password."]})
    
        # return attributes
        return attrs

    def create(self, validated_data):
        """Create new user"""
        validated_data.pop("password2")
        
        user = User(
            username = validated_data['username'],
            email = validated_data['email'],
            is_verified=False,
        )
        user.set_password(validated_data['password'])
        user.save()
        
        return user

class LoginSerializer(serializers.Serializer):
    """Login Serializer"""
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, style={'input': 'password'})
    
    def save(self, validated_data):
        """Save method for authenticate user"""
        username, password = [validated_data['username'], validated_data['password']]
        try:
            user = User.objects.get(username=username)
            if not user.is_verified:
                raise serializers.ValidationError({"user": "Your account is not verified please verify it at first"}, status.HTTP_401_UNAUTHORIZED)
            
            if not user.check_password(password):
                raise serializers.ValidationError({"user": "Username or Password is incorrect"}, status.HTTP_401_UNAUTHORIZED)
            
            validated_data['user'] = user
            return user
            
        except User.DoesNotExist:
            raise serializers.ValidationError({"user": "Username or Password is incorrect"}, status.HTTP_401_UNAUTHORIZED)
        
        

class ActivateAccountSerializer(serializers.Serializer):
    """Serialize for activating user account via uid and token"""
    uid = serializers.CharField()
    token = serializers.CharField()
    
    def validate(self, attrs):
        """Validate uid and token for registration"""
        try:
            uid = force_str(urlsafe_base64_decode(attrs['uid']))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError({"uid": 'Invalid User ID'})
        
        if not default_token_generator.check_token(user, attrs['token']):
            raise serializers.ValidationError({"token": "Invalid or expired token"})
        
        attrs['user'] = user
        return attrs
    
    def save(self, **kwargs):
        """Activate user account"""
        user = self.validated_data['user']
        user.is_verified=True
        user.save()
        return user
    

class PasswordChangeSerializer(serializers.Serializer):
    """
    Serializer for changing password
    """
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    new_password2 = serializers.CharField(required=True)
    
    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect.")
        return value
    
    def validate(self, attrs):
        old_password, new_password, new_password2 = [
            attrs['old_password'],
            attrs['new_password'],
            attrs['new_password2']
        ]
        if new_password != new_password2:
            raise serializers.ValidationError({"new_password": "Password fields didn't match."})
        
        user = self.context['request'].user
        
        # Use your PasswordService for validation
        is_valid, errors = PasswordService.validate(
            new_password, 
            user.username, 
            user.email
        )
        
        if not is_valid:
            raise serializers.ValidationError({"new_password": errors})
        
        # Check for password leak
        if PasswordService.is_password_pwned(new_password):
            raise serializers.ValidationError({
                "new_password": ["Password is leaked in security breaches, please choose a more secure password."]
            })
            
        return attrs
    
    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()
        return user

class PasswordResetRequestSerializer(serializers.Serializer):
    """
    Serializer for requesting password reset
    """
    email = serializers.EmailField(required=True)
    
    def validate_email(self, value):
        try:
            User.objects.get(email=value)
        except User.DoesNotExist:
            raise serializers.ValidationError({"email": "If you're email was register, you may get a reset password link"})
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    """
    Serializer for confirming password reset
    """
    uid = serializers.CharField(required=True)
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    new_password2 = serializers.CharField(required=True)
    
    def validate(self, attrs):
        # Validate UID and token
        try:
            uid = force_str(urlsafe_base64_decode(attrs['uid']))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            raise serializers.ValidationError({"uid": "Invalid user ID"})
            
        if not default_token_generator.check_token(user, attrs['token']):
            raise serializers.ValidationError({"token": "Invalid or expired token"})
        
        # Validate password
        if attrs['new_password'] != attrs['new_password2']:
            raise serializers.ValidationError({"new_password": "Password fields didn't match."})
        
        # Use your PasswordService for validation
        is_valid, errors = PasswordService.validate(
            attrs['new_password'], 
            user.username, 
            user.email
        )
        
        if not is_valid:
            raise serializers.ValidationError({"new_password": errors})
        
        # Check for password leak
        if PasswordService.is_password_pwned(attrs['new_password']):
            raise serializers.ValidationError({
                "new_password": ["Password is leaked in security breaches, please choose a more secure password."]
            })
        
        attrs['user'] = user
        return attrs
    
    def save(self):
        user = self.validated_data['user']
        user.set_password(self.validated_data['new_password'])
        user.reset_failures()  # Reset any failed login attempts
        if user.is_banned:
            user.unban_user()  # Unban user if they were banned
        user.save()
        return user