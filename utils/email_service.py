from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.conf import settings
from accounts.models import User


class EmailService():
    
    @staticmethod
    def send_activation_link(user: User, uid: str, token: str) -> bool:
        # Create activation URL for frontend
        activation_link = f"{settings.FRONTEND_URL}/activate/{uid}/{token}/"
        
        try:
            # Send activation email
            mail_subject = 'Activate your Playlist Founder account'
            message = render_to_string('email/account_activation_email.html', {
                'user': user,
                'activation_link': activation_link,
            })
            email = EmailMessage(mail_subject, message, to=[user.email])
            email.content_subtype = "html"
            email.send()
            return True
        except Exception as e:
            return False
    
    @staticmethod
    def send_reset_password_link(user: User, uid: str, token: str) -> bool:
        # Create reset URL for frontend
        reset_link = f"{settings.FRONTEND_URL}/reset-password/{uid}/{token}/"
        
        # Send reset email
        mail_subject = 'Reset your Playlist Founder password'
        message = render_to_string('email/password_reset_email.html', {
            'user': user,
            'reset_link': reset_link,
        })
        email = EmailMessage(mail_subject, message, to=[user.email])
        email.content_subtype = "html"
        email.send()
        
        # Increment forget attempts to prevent abuse
        user.increment_failed(type="forgot")