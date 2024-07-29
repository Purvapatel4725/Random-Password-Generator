import tkinter as tk
from tkinter import messagebox
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

# GUI application
class PasswordGeneratorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Random Password Generator")
        self.geometry("400x400")
        
        self.create_widgets()
    
    def create_widgets(self):
        # Length input
        tk.Label(self, text="Password Length:", anchor="w").pack(fill="x", padx=10, pady=5)
        self.length_var = tk.IntVar(value=8)
        tk.Entry(self, textvariable=self.length_var).pack(fill="x", padx=10, pady=5)
        
        # Uppercase checkbox
        self.uppercase_var = tk.BooleanVar()
        tk.Checkbutton(self, text="Include Uppercase Letters", variable=self.uppercase_var, anchor="w").pack(fill="x", padx=10, pady=5)
        
        # Numbers checkbox
        self.numbers_var = tk.BooleanVar()
        tk.Checkbutton(self, text="Include Numbers", variable=self.numbers_var, anchor="w").pack(fill="x", padx=10, pady=5)
        
        # Special characters checkbox
        self.special_var = tk.BooleanVar()
        tk.Checkbutton(self, text="Include Special Characters", variable=self.special_var, anchor="w").pack(fill="x", padx=10, pady=5)
        
        # Pattern choice
        tk.Label(self, text="Password Pattern:", anchor="w").pack(fill="x", padx=10, pady=5)
        self.pattern_var = tk.StringVar(value='')
        tk.Radiobutton(self, text="Start with Letter", variable=self.pattern_var, value="start_with_letter", anchor="w").pack(fill="x", padx=10, pady=5)
        tk.Radiobutton(self, text="End with Number", variable=self.pattern_var, value="end_with_number", anchor="w").pack(fill="x", padx=10, pady=5)
        tk.Radiobutton(self, text="No Pattern", variable=self.pattern_var, value="", anchor="w").pack(fill="x", padx=10, pady=5)
        
        # Encryption key input
        tk.Label(self, text="Encryption Key (Optional):", anchor="w").pack(fill="x", padx=10, pady=5)
        self.key_var = tk.StringVar()
        tk.Entry(self, textvariable=self.key_var).pack(fill="x", padx=10, pady=5)
        
        # Generate button
        tk.Button(self, text="Generate Password", command=self.generate_password).pack(pady=20)
        
        # Result area
        tk.Label(self, text="Result:", anchor="w").pack(fill="x", padx=10, pady=5)
        self.result_text = tk.Text(self, height=8, width=50, wrap=tk.WORD)
        self.result_text.pack(padx=10, pady=5)
    
    def generate_password(self):
        try:
            length = self.length_var.get()
            use_uppercase = self.uppercase_var.get()
            use_numbers = self.numbers_var.get()
            use_special = self.special_var.get()
            pattern = self.pattern_var.get()
            key_input = self.key_var.get()
            
            key = None
            if key_input:
                key = base64.urlsafe_b64encode(key_input.encode())
            
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
            
            result_text = f"Generated Password: {decrypted_password}\nPassword Strength: {strength}"
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, result_text)
        
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    app = PasswordGeneratorApp()
    app.mainloop()
