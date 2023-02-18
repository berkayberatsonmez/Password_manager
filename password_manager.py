import random
import string
import pickle
from cryptography.fernet import Fernet

import string
import pickle
from cryptography.fernet import Fernet


def generate_password(length):
    # Generate a random password using letters, digits, and special characters
    chars = string.ascii_letters + string.digits + "!@#$%^&*()_+=-"
    password = "".join(random.choice(chars) for i in range(length))
    return password

# Specify the desired password length
password_length = 16

# Initialize an empty dictionary to store the encrypted passwords and their key names
passwords = {}

# Generate an encryption key
key = Fernet.generate_key()

# Initialize a Fernet object using the encryption key
fernet = Fernet(key)

# File names for saving the encryption key and encrypted passwords
key_file = "key.key"
password_file = "passwords.pickle"

# Load the encryption key from a file (if it exists)
try:
    with open(key_file, "rb") as f:
        key = f.read()
    fernet = Fernet(key)
except FileNotFoundError:
    # If the file doesn't exist, generate a new key
    key = Fernet.generate_key()
    fernet = Fernet(key)
    with open(key_file, "wb") as f:
        f.write(key)

# Store a username and password for the login system
username = "admin"
password = "123456"
encrypted_password = fernet.encrypt(password.encode())

# Load the encrypted passwords from a file (if it exists)
try:
    with open(password_file, "rb") as f:
        passwords = pickle.load(f)
except FileNotFoundError:
    # If the file doesn't exist, initialize an empty dictionary
    passwords = {}

# Loop to add multiple passwords to the dictionary
# Loop to add multiple passwords to the dictionary
while True:
    
    user_input = input("Enter your username: ")
    if user_input == "q":
        break
    elif user_input != username:
        print("Incorrect username. Please try again.")
        continue

    user_input = input("Enter your password: ")
    decrypted_password = fernet.decrypt(encrypted_password).decode()
    if user_input != decrypted_password:
        print("Incorrect password. Please try again.")
        continue

    print("Login successful.")

    # Loop to add multiple passwords to the dictionary
    while True:
        # Ask the user for a key name
        user_input = input("Enter 'q' to quit, 's' to save a password, 'v' to view a password, 'd' to delete a password, or 'c' to clear the password store:")

        # Quit if the user enters 'q'
        if user_input == 'q':
            break
        elif user_input == 's':
        # Save a password
            print("Enter a name for the password:")
            password_name = input()
            if password_name in passwords:
                print("Password name already exists. Please choose a different name.")
            else:
                print("Enter 'c' to cancel, or hit Enter to generate a password:")
                cancel = input()
                if cancel == 'c':
                    continue
                password = generate_password(password_length)
                encrypted_password = fernet.encrypt(password.encode())

                # Store the encrypted password in the dictionary
                passwords[password_name] = encrypted_password

        elif user_input == 'v':
            # View a password
            key_name = input("\nEnter a key name to retrieve the password: ")
            if key_name not in passwords:
                print("Password name not found. Please try again.")
            else:
                encrypted_password = passwords[key_name]
                password = fernet.decrypt(encrypted_password).decode()
                print(f"\nPassword for {key_name}: {password}")
        elif user_input == 'd':
            # Delete a password
            key_name = input("\nEnter a key name to delete the password: ")
            if key_name not in passwords:
                print("Password name not found. Please try again.")
            else:
                confirmation = input(f"Are you sure you want to delete the {key_name} password? (y/n): ")
                if confirmation == 'y':
                    print("Password deleted.")
                    del passwords[key_name]
                else:
                    print("Password not deleted.")
        elif user_input == 'c':
            # Clear the password store
            confirmation = input("Are you sure you want to clear the password store? (y/n): ")
            if confirmation == 'y':
                print("Password store cleared.")
                passwords.clear()
            else:
                print("Password store not cleared.")

        else:
            # Invalid input
            print("Invalid input. Please try again.")


# Save the encrypted passwords to a file
with open(password_file, "wb") as f:
    pickle.dump(passwords, f)



