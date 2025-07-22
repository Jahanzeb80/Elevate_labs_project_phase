Steganography Tool  - made by Cyber Warrior

Overview

This is a "Stegnography" tool made with python and tkinter GUI.
its allow you to "Hide any secret text or file inside an image (the image format it supports PNG/BMP )"  with passwrod protection and AES encryption using fernet.

Features

Hide any secret text inside an image (you can type any message using the given text box)  
Hide any type of file inside an image (txt,pdf,or any payload we can say)  
Password-protected encryption using PBKDF2 + Fernet (AES-128)  
Supports PNG and BMP formats (the image formats it supports)  
Extract and decrypt data securely  
Beginner-friendly GUI (for non technical users)


How it works 
Choose what to hide (text/file)
set a password (only you know)
embeed in the image (select an image to embeed)
save the stego image (with you desired path and name)
Extract When Needed (select the stego image and enter the correct password if its text it will show on screen if its file it asks you say the file so save where you want to save it)


Requirements

- Python 3.x
- [`cryptography`](https://pypi.org/project/cryptography/)
- [`Pillow`](https://pypi.org/project/Pillow/)

