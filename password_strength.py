import tkinter as tk
from tkinter import messagebox
import re

# Password strength checker function
def password_strength_checker(password):
    strength_level = 0

    # Criteria 1: password length
    if len(password) >= 12:
        strength_level += 2
    elif 8 <= len(password) < 12:
        strength_level += 1

    # Criteria 2: Uppercase and lowercase characters
    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        strength_level += 1

    # Criteria 3: Numbers
    if re.search(r'\d', password):
        strength_level += 1

    # Criteria 4: Special characters
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        strength_level += 1

    # Criteria 5: Uniqueness
    if len(set(password)) > len(password) / 2:
        strength_level += 1

    # Give feedback according to the level of strength
    if strength_level >= 5:
        return "Strong"
    elif 3 <= strength_level < 5:
        return "Medium"
    else:
        return "Weak"

# Password strength check function handling when button is clicked
def check_password_strength():
    password = password_entry.get()
    if password:
        strength = password_strength_checker(password)
        result_label.config(text=f"Password Strength: {strength}", fg="green" if strength == "Strong" else "orange" if strength == "Medium" else "red")
    else:
        messagebox.showwarning("Input Error", "Please enter a password.")

# Create the main window
root = tk.Tk()
root.title("Password Strength Checker")
root.geometry("400x300")
root.resizable(False, False)
root.config(bg="#f4f4f9")

# Create a frame for the input area
frame = tk.Frame(root, bg="#f4f4f9")
frame.pack(pady=30)

# Password entry label and entry field
password_label = tk.Label(frame, text="Enter your password:", font=("Helvetica", 12), bg="#f4f4f9")
password_label.pack(pady=5)

password_entry = tk.Entry(frame, font=("Helvetica", 14), show="*", width=30, bd=2, relief="solid")
password_entry.pack(pady=5)

# Button to check password strength
check_button = tk.Button(root, text="Check Strength", font=("Helvetica", 14), bg="#4CAF50", fg="white", command=check_password_strength)
check_button.pack(pady=20)

# Label to display the strength result
result_label = tk.Label(root, text="Password Strength:", font=("Helvetica", 14), bg="#f4f4f9", fg="gray")
result_label.pack()

# Run the application
root.mainloop()
