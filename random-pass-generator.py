import random
import string
from cryptography.fernet import Fernet
import base64

# Initialize a list to keep track of generated passwords
password_history = set()

# Generate a cryptographic key for encryption
def generate_key():
    return base64.urlsafe_b64encode(Fernet.generate_key())

# Encrypt the password
def encrypt_password(password, key):
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password

# Decrypt the password
def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    return decrypted_password

# Generate a random password
def generate_password(length, use_uppercase, use_numbers, use_special, pattern, key):
    # Define character sets
    char_sets = {
        'lowercase': string.ascii_lowercase,
        'uppercase': string.ascii_uppercase,
        'numbers': string.digits,
        'special': string.punctuation
    }
    
    # Default character sets with lower case letters being the predominant
    characters = char_sets['lowercase']
    proportions = {'lowercase': 1.5}
    
    if use_uppercase:
        characters += char_sets['uppercase']
        proportions['uppercase'] = 1.0
    if use_numbers:
        characters += char_sets['numbers']
        proportions['numbers'] = 0.8
    if use_special:
        characters += char_sets['special']
        proportions['special'] = 0.5

    # Ensure that characters are selected
    if not characters:
        raise ValueError("At least one character set must be selected.")

    # Generate the password based on pattern
    password = ''
    if pattern:
        if pattern == 'start_with_letter':
            password += random.choice(char_sets['lowercase'] + char_sets['uppercase'])
            length -= 1
        elif pattern == 'end_with_number':
            password += random.choice(char_sets['numbers'])
            length -= 1

    # Add characters in proportion to their defined weights
    while length > 0:
        char_type = random.choices(
            list(proportions.keys()),
            weights=list(proportions.values()),
            k=1
        )[0]
        if char_type == 'lowercase':
            password += random.choice(char_sets['lowercase'])
        elif char_type == 'uppercase' and use_uppercase:
            password += random.choice(char_sets['uppercase'])
        elif char_type == 'numbers' and use_numbers:
            password += random.choice(char_sets['numbers'])
        elif char_type == 'special' and use_special:
            password += random.choice(char_sets['special'])
        length -= 1

    # Check for complexity rules
    if use_uppercase and not any(c.isupper() for c in password):
        password += random.choice(char_sets['uppercase'])
    if use_numbers and not any(c.isdigit() for c in password):
        password += random.choice(char_sets['numbers'])
    if use_special and not any(c in string.punctuation for c in password):
        password += random.choice(char_sets['special'])
    
    # Shuffle the password to randomize the order of characters
    password = ''.join(random.sample(password, len(password)))
    
    # Ensure password uniqueness
    if password in password_history:
        return generate_password(length, use_uppercase, use_numbers, use_special, pattern, key)
    
    # Add password to history
    password_history.add(password)
    
    # Encrypt the password if a key is provided
    if key:
        encrypted_password = encrypt_password(password, key)
        return encrypted_password
    else:
        return password

# Evaluate password strength
def evaluate_strength(password):
    length_score = len(password) >= 12
    upper_score = any(c.isupper() for c in password)
    lower_score = any(c.islower() for c in password)
    number_score = any(c.isdigit() for c in password)
    special_score = any(c in string.punctuation for c in password)
    
    scores = [length_score, upper_score, lower_score, number_score, special_score]
    strength = sum(scores) / len(scores)
    
    if strength >= 0.8:
        return "Strong"
    elif strength >= 0.6:
        return "Moderate"
    else:
        return "Weak"

# Function to display menu and get user input
def get_user_input():
    print("\nRandom Password Generator")
    print("------------------------")
    
    length = int(input("Enter password length (default is 8): ") or 8)
    use_uppercase = input("Include uppercase letters? (y/n): ").strip().lower() == 'y'
    use_numbers = input("Include numbers? (y/n): ").strip().lower() == 'y'
    use_special = input("Include special characters? (y/n): ").strip().lower() == 'y'
    pattern = input("Specify a pattern (start_with_letter/end_with_number, or leave blank): ").strip() or None
    key_input = input("Enter an encryption key (or leave blank to skip encryption): ").strip()
    
    key = None
    if key_input:
        key = base64.urlsafe_b64encode(key_input.encode())
    
    return length, use_uppercase, use_numbers, use_special, pattern, key

# Main function to run the program
def main():
    length, use_uppercase, use_numbers, use_special, pattern, key = get_user_input()
    
    # Generate password
    generated_password = generate_password(
        length,
        use_uppercase,
        use_numbers,
        use_special,
        pattern,
        key
    )
    
    # Decrypt the password if a key was used for encryption
    if key:
        decrypted_password = decrypt_password(generated_password, key)
    else:
        decrypted_password = generated_password

    strength = evaluate_strength(decrypted_password)
    
    print(f"\nGenerated Password: {decrypted_password}")
    print(f"Password Strength: {strength}")

if __name__ == "__main__":
    main()
