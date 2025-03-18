import random
import string
import bcrypt
import re

class PasswordGenerator:
    def __init__(self, length=12, use_uppercase=True, use_lowercase=True, use_numbers=True, use_special=True):
        self.length = length
        self.use_uppercase = use_uppercase
        self.use_lowercase = use_lowercase
        self.use_numbers = use_numbers
        self.use_special = use_special

    def generate_password(self):
        character_pool = ''
        if self.use_uppercase:
            character_pool += string.ascii_uppercase
        if self.use_lowercase:
            character_pool += string.ascii_lowercase
        if self.use_numbers:
            character_pool += string.digits
        if self.use_special:
            character_pool += string.punctuation

        if not character_pool:
            raise ValueError("At least one character type must be selected.")

        password = ''.join(random.choice(character_pool) for _ in range(self.length))
        return password

class PasswordStrengthChecker:
    def check_strength(self, password):
        length_score = len(password) >= 12
        upper_score = re.search(r'[A-Z]', password) is not None
        lower_score = re.search(r'[a-z]', password) is not None
        number_score = re.search(r'[0-9]', password) is not None
        special_score = re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None

        score = sum([length_score, upper_score, lower_score, number_score, special_score])

        strength = "Weak"
        if score >= 4:
            strength = "Strong"
        elif score == 3:
            strength = "Moderate"

        return strength, self.get_security_insights(password)

    def get_security_insights(self, password):
        insights = []
        if len(password) < 12:
            insights.append("Consider using at least 12 characters.")
        if not re.search(r'[A-Z]', password):
            insights.append("Include at least one uppercase letter.")
        if not re.search(r'[a-z]', password):
            insights.append("Include at least one lowercase letter.")
        if not re.search(r'[0-9]', password):
            insights.append("Include at least one number.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            insights.append("Include at least one special character.")
        if re.search(r'(.)\1{2,}', password):
            insights.append("Avoid repeating characters.")
        if len(set(password)) < len(password) / 2:
            insights.append("Avoid using too many similar characters.")

        return insights

class PasswordStorage:
    @staticmethod
    def hash_password(password):
        # Generate a salt and hash the password
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password

# Example usage
if __name__ == "__main__":
    # Password Generation
    generator = PasswordGenerator(length=16, use_uppercase=True, use_lowercase=True, use_numbers=True, use_special=True)
    new_password = generator.generate_password()
    print(f"Generated Password: {new_password}")

    # Password Strength Checking
    checker = PasswordStrengthChecker()
    strength, insights = checker.check_strength(new_password)
    print(f"Password Strength: {strength}")
    print("Security Insights:")
    for insight in insights:
        print(f"- {insight}")

    # Password Storage
    hashed_password = PasswordStorage.hash_password(new_password)
    print(f"Hashed Password: {hashed_password.decode('utf-8')}")
