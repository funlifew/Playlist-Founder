from rest_framework import generics, status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import get_user_model
from django.utils import timezone
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
        
        # activation link
        activation_link = f"{settings.FRONTEND_URL}/activate/{uid}/{token}/"
        
        # Send activation email
        mail_subject = 'Activate your Playlist Founder account'
        message = render_to_string('account_activation_email.html', {
            'user': user,
            'activation_link': activation_link,
        })
        email = EmailMessage(mail_subject, message, to=[user.email])
        email.content_subtype = "html"
        email.send()
        
        return Response({
            "message": "User registered successfully. Please check your email to activate your account."
        }, status=status.HTTP_201_CREATED)