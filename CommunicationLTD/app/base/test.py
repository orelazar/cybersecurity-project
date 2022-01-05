from passlib.hash import sha256_crypt

def hash_pass(password):
   password_hased = sha256_crypt.encrypt(password)
   return password_hased


def verify_pass(provided_password, stored_password):
    return sha256_crypt.verify(provided_password,stored_password)


password = "passwor123d"
hased2 = hash_pass(password)
hased = hash_pass(password)
print(hased + "\n")
print(verify_pass(password,hased))
print(hased2+ "\n")
print(verify_pass(password,hased2))




 
