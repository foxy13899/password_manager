    # PASSWORD MANAGER
    #### Video Demo:  <URL HERE>
    #### Description: This is a simple password manager that stores encrypte passwords as per their platforms 

It uses AES encryption to encrypt the passwords in the json file, where they are stored in the form of platform{name, pass}

it stores the masterpassword in a sha 512 hash to ensure that someone with the system may not read it there is also an initialisation system to create the password for the first time
