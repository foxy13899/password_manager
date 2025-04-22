import hashlib
import string
import dotenv
import os
import random
import json
import base64
from tabulate import tabulate
import sys
from Crypto import Random
from Crypto.Cipher import AES

h_512 = hashlib.sha512()
input_prompt = "----> "


class encryptor:
    def __init__(self, key):
        self.key = key

    def pad(self, s):
        return s + b'\0' * (AES.block_size - len(s) % AES.block_size)

    def encrypt(self, key, message, key_size=256):
        message = self.pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)

    def decrypt(self, cipherText, key):
        iv = cipherText[:AES.block_size]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(cipherText[AES.block_size:])
        return plaintext.rstrip(b'\0')

def createpass(length=10, use_only_charactersandnum=False) -> str:
    if use_only_charactersandnum:
        letters = string.ascii_letters + string.digits
    else:
        letters = string.ascii_letters + string.digits + string.punctuation

    return ''.join(random.choice(letters) for _ in range(length))

def add_pass(name : str, password : str, platform: str, pass_file: str, enc: encryptor, aeskey: bytes, passes: dict) -> None:
            #the details are encrypted in aes, but to save it in json we encode it in bytes

            encrypted_platform = base64.b64encode(enc.encrypt(aeskey, platform.encode())).decode('utf-8')
            encrypted_name = base64.b64encode(enc.encrypt(aeskey, name.encode())).decode('utf-8')
            encrypted_password = base64.b64encode(enc.encrypt(aeskey, password.encode())).decode('utf-8')
            
            #saving passes then writing it into the json file

            passes[encrypted_platform] = [encrypted_name, encrypted_password]
            try:
                
                with open(pass_file, 'w',encoding='utf-8') as f:
                    json.dump(passes, f, indent=4)
            except FileNotFoundError:
                raise FileNotFoundError(f"File name {pass_file} does not exist")

def view_pass(platform : str, enc: encryptor, aeskey: bytes, passes: dict) -> dict:
    enc = encryptor(aeskey)
    platforms = passes.keys()
    platforms_decrypted = []
    #this was a security flaw
    if not platform:
        raise ValueError("please enter a platform")
    
    #we take the keys of the json we have stored, then reverse the encryption and encoding
    for i, plt in enumerate(platforms):
        based = base64.b64decode(plt)
        pltd = enc.decrypt(based,aeskey).decode('utf-8')
        platforms_decrypted.append(pltd)
    found = {}    
    if platform not in platforms_decrypted:
            print(f"no passwords found for {platform}.")
            return None
    for i,pltforms in enumerate(platforms_decrypted):            

        if pltforms == platform:
        #we pull the name and password from the passes, which is encrypted and so we decrypt them
            name_encrypted, password_encrypted = passes[list(platforms)[i]]
            based_name = base64.b64decode(name_encrypted)
            name_decrypted = enc.decrypt(based_name,aeskey).decode('utf-8')
            based_pass = base64.b64decode(password_encrypted)
            pass_decrypted = enc.decrypt(based_pass,aeskey).decode('utf-8')
            found.update({name_decrypted : pass_decrypted})
    return found
                
def takeInput(prompt = "") -> str:
    try:
        text = input("---->" if not prompt else prompt)
        if text == "":
            print("No input detected")
            return 0
        if text == "clr":
            os.system('cls')
            return ""
        else:
            return text
    except KeyboardInterrupt or EOFError:
        sys.exit("GoodBye...")

def initialisepassword():  
    h_512 = hashlib.sha512()
    master_hash = dotenv.get_key('pass.env', 'masterkey')    
    if master_hash =="":
        
        print("No password detected, please make a new password: ")
        newpass = input("New password: ").strip()
        reenter = input("Re-enter password: ").strip()

        if newpass != reenter:
            sys.exit("passwords did not match.")
        h_512.update(newpass.encode())
        dotenv.set_key('pass.env', 'masterkey',h_512.hexdigest())
        sys.exit("password set successfully, please restart.")
        
        
    if not master_hash:
        print("Error: Master key not found in the environment file.")
        exit()

def main():
    initialisepassword()
    master_hash = dotenv.get_key('pass.env', 'masterkey')
    
    key = takeInput("To continue, please enter your password: ")
    h_512.update(key.encode())
    
    if h_512.hexdigest() == master_hash:
        print("Authorized.")
    else:
        print("Incorrect password.")
        exit()
        
    h_512.update(key.encode())
    aeskey = hashlib.sha256(key.encode()).digest()
    
    enc = encryptor(aeskey)
       
    #reads pass.json before to make it easier after this
    try:
        with open('pass.json', 'r') as f:
           passes = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        passes = {}
    
    print("Options:",
          "1: Add or change a password",
          "2: View a password",
          "3: Generate a new password",
          "4: view saved password platforms",
          "5 or KeyboardInterrupt: exit",
          "clr: clear screen",
          "options: Show this menu",sep="\n")
    while True:
        try:
            choice = takeInput()
        except KeyboardInterrupt:
            print("goodbye...")
            exit()
        if choice == '1':
            platform = takeInput("Please enter the platform: ")
            name = takeInput("Please enter your account name or identifier: ")
            password = takeInput("Please enter the password: ")
            

            
            if (not platform) or (not name) or (not password):
                print("Invalid Values provided")
                continue
            
            add_pass(name,password,platform,pass_file='pass.json', enc= enc, aeskey=aeskey, passes=passes)
            print("Password added successfully.")


        elif choice == '2':
            platform = takeInput("Please enter the platform: ")
            if platform == 0 :
                continue
            idpass = view_pass(platform, enc=enc, aeskey=aeskey, passes=passes)
            if not idpass:
                continue
            print(tabulate({"account": idpass.keys(),
                            "passwords": idpass.values()}, headers='keys'))
        
        elif choice == '3':
            length = int(takeInput("Enter password length: "))
            use_only_chars = str(takeInput("Use only characters and numbers? (y/n): ")).lower() == 'y'
            new_password = createpass(length, use_only_chars)
            if length == 0 or use_only_chars == 0 or new_password == 0:
                continue
            print(f"Generated Password: {new_password}")
        
        elif choice == "4":
            
            platforms_1 = []
            for platform in passes.keys():
                based = base64.b64decode(platform)
                decrypted= enc.decrypt(based,aeskey).decode('utf-8')
                if decrypted == "":
                    continue
                platforms_1.append(enc.decrypt(based,aeskey).decode('utf-8'))
            count =[]
            for plt in sorted(set(platforms_1)):  
                count.append(platforms_1.count(plt))
            
            print(tabulate({"Platform name": sorted(set(platforms_1)), 
                            "Password count": count}, headers='keys'))
                    
        elif choice == '5':
            print("Goodbye...")
            os.system('cls')
            exit()
        
        elif choice == "options":
            print("Options:",
            "1: Add or change a password",
            "2: View a password",
            "3: Generate a new password",
            "4: view saved password platforms",
            "5 or KeyboardInterrupt: exit",sep="\n")
            
        elif choice == "":
            pass
        else:
            print("Invalid choice.")


if __name__ == '__main__':
    main()