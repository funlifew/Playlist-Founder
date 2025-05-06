from django.contrib.auth.tokens import PasswordResetTokenGenerator
import six

class AccountActivationTokenGenerator(PasswordResetTokenGenerator):
    """Token generator for account activation"""
    
    def _make_hash_value(self, user, timestamp):
        """Create unique hash based on user_state"""
        return (
            six.text_type(user.pk),
            six.text_type(timestamp),
            six.text_type(user.is_verified),
        )

account_activation_token = AccountActivationTokenGenerator()