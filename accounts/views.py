from rest_framework import generics, status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.utils import timezone
from django.conf import settings
from utils.email_service import EmailService

from .serializers import (
    UserSerializer,
    RegisterSerializer,
    PasswordChangeSerializer,
    ActivateAccountSerializer,
    PasswordResetRequestSerializer,
    PasswordResetConfirmSerializer
)

from .tokens import account_activation_token

User = get_user_model()
# Create your views here.

class RegisterView(generics.CreateAPIView):
    """API View for register a new user"""

    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]
    
    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        
        # generate activation link
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = account_activation_token.make_token(user)
        
        # Send Activation Link
        EmailService.send_activation_link(user, uid, token)
        
        return Response({
            "message": "User registered successfully. Please check your email to activate your account."
        }, status=status.HTTP_201_CREATED)

class ActivateAccountView(generics.GenericAPIView):
    """API endpoint for account activation"""
    
    serializer_class = ActivateAccountSerializer
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = self.get_serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        return Response({
            "message": "Account activated successfully. You can now login."
        }, status=status.HTTP_200_OK)

class PasswordResetRequestView(generics.GenericAPIView):
    serializer_class = PasswordResetRequestSerializer
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        
        try:
            # Get user by email
            user = User.objects.get(email=email)
            
            # guard clause for user ban statement
            if user.is_banned:
                # Don't reveal ban status
                return Response({
                    "message": "If your email is registered, you will receive a password reset link."
                }, status=status.HTTP_200_OK)
            
            # Generate uid and token
            
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = account_activation_token.make_token(user)
            
            EmailService.send_reset_password_link(user, uid, token)
            
            # Increment forget attempts to prevent abuse
            user.increment_failed(type="forgot")
        except User.DoesNotExist:
            pass
        
        return Response({
            "message": "If your email is registered, you will receive a password reset link."
        }, status=status.HTTP_200_OK)