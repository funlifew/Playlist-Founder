import re, hashlib, requests
from typing import Tuple, List

class PasswordService:
    
    # Common Password List
    COMMON_PASSWORDS = (
        'password', '123456', 'qwerty', 'admin', 'welcome',
        '12345678', '123456789', '987654321', '87654321', 'abc123',
        'password1', '1234567'
    )
    
    @staticmethod
    def validate(password: str, username: str="", email: str="")->Tuple[bool, List[str]]:
        errors = []
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        
        # check complexity
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")
        
        if not re.search(r'[0-9]', password):
            errors.append("Password must contain at least one digit")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Password must contain at least one special character")
        
        # check against username, email
        if username and username.lower() in password.lower():
            errors.append("Password cannot contain your username")
        
        if email:
            email_parts = email.split('@')[0]
            if email_parts.lower() in password.lower():
                errors.append("Password cannot contain your email")
        
        # check common password:
        if password.lower() in PasswordService.COMMON_PASSWORDS:
            errors.append("Password is too common and easily guessable")
        
        # Check for sequences and repetitions
        if re.search(r'(.)\1\1', password):
            errors.append("Password contains too many repeated characters")
        
        if any(seq in password.lower() for seq in ["123", "abc", "qwe", "xyz"]):
            errors.append("Password contains common sequences")
        
        return len(errors) == 0, errors

    @staticmethod
    def is_password_pwned(password: str) -> bool:
        """
        Check if password is in the Have I Been Pwned database
        Using k-Anonymity model for privacy
        """
        
        # Create SHA-1 hash of the password
        password_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        
        # Get the first 5 characters of the hash
        prefix = password_hash[:5]
        
        # Get the rest of the hash
        suffix = password_hash[5:]
        
        # API request to HIBP
        try:
            response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            if response.status_code == 200:
                # Check if our hash suffix is in the response
                return suffix in response.text
            return False
        except:
            # If there's any error, assume the password is secure (don't block on API failure)
            return False
    