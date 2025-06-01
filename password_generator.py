import random
import string
import tkinter as tk
from tkinter import ttk, messagebox

class PasswordGenerator:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Password Generator")
        self.window.geometry("400x500")
        self.window.configure(bg="#f0f0f0")
        
        # Create and configure style
        self.style = ttk.Style()
        self.style.configure("TButton", padding=5, font=('Arial', 10))
        self.style.configure("TCheckbutton", font=('Arial', 10))
        self.style.configure("TLabel", font=('Arial', 10))
        
        self.create_widgets()
        
    def create_widgets(self):
        # Title
        title_label = ttk.Label(
            self.window,
            text="Password Generator",
            font=('Arial', 16, 'bold')
        )
        title_label.pack(pady=20)
        
        # Length frame
        length_frame = ttk.Frame(self.window)
        length_frame.pack(pady=10)
        
        ttk.Label(length_frame, text="Password Length:").pack(side=tk.LEFT, padx=5)
        self.length_var = tk.StringVar(value="12")
        length_entry = ttk.Entry(length_frame, textvariable=self.length_var, width=5)
        length_entry.pack(side=tk.LEFT)
        
        # Options frame
        options_frame = ttk.LabelFrame(self.window, text="Password Options")
        options_frame.pack(pady=10, padx=20, fill="x")
        
        self.uppercase_var = tk.BooleanVar(value=True)
        self.lowercase_var = tk.BooleanVar(value=True)
        self.numbers_var = tk.BooleanVar(value=True)
        self.special_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="Uppercase Letters (A-Z)", variable=self.uppercase_var).pack(anchor="w", pady=2)
        ttk.Checkbutton(options_frame, text="Lowercase Letters (a-z)", variable=self.lowercase_var).pack(anchor="w", pady=2)
        ttk.Checkbutton(options_frame, text="Numbers (0-9)", variable=self.numbers_var).pack(anchor="w", pady=2)
        ttk.Checkbutton(options_frame, text="Special Characters (!@#$%^&*)", variable=self.special_var).pack(anchor="w", pady=2)
        
        # Generate button
        generate_btn = ttk.Button(
            self.window,
            text="Generate Password",
            command=self.generate_password
        )
        generate_btn.pack(pady=20)
        
        # Result frame
        result_frame = ttk.LabelFrame(self.window, text="Generated Password")
        result_frame.pack(pady=10, padx=20, fill="x")
        
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(
            result_frame,
            textvariable=self.password_var,
            font=('Courier', 12),
            state='readonly'
        )
        password_entry.pack(pady=10, padx=10, fill="x")
        
        # Copy button
        copy_btn = ttk.Button(
            self.window,
            text="Copy to Clipboard",
            command=self.copy_to_clipboard
        )
        copy_btn.pack(pady=10)
        
    def generate_password(self):
        try:
            length = int(self.length_var.get())
            if length < 4:
                messagebox.showerror("Error", "Password length must be at least 4 characters!")
                return
                
            # Get selected character sets
            chars = ""
            if self.uppercase_var.get():
                chars += string.ascii_uppercase
            if self.lowercase_var.get():
                chars += string.ascii_lowercase
            if self.numbers_var.get():
                chars += string.digits
            if self.special_var.get():
                chars += string.punctuation
                
            if not chars:
                messagebox.showerror("Error", "Please select at least one character type!")
                return
                
            # Generate password
            password = ''.join(random.choice(chars) for _ in range(length))
            self.password_var.set(password)
            
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for password length!")
            
    def copy_to_clipboard(self):
        password = self.password_var.get()
        if password:
            self.window.clipboard_clear()
            self.window.clipboard_append(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "Generate a password first!")
            
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = PasswordGenerator()
    app.run() 