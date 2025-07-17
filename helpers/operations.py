from helpers import pss
from helpers import rsa
import base64, os, time
from datetime import datetime

# USED ONLY FOR PEM SERIALIZATION
from cryptography.hazmat.primitives.asymmetric import rsa as rsaModule
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

TEST_FLAG = False
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

"""
Generates and stores Keys (and returns time elapsed during key generation)
"""
def generate_keys() -> float:
    
    while True:
        clear_screen()
        print("Signature Generator and Verifier: Key Generation")
        print("Choose type of file to store key:\n| 1. Custom .custom_key format (only b64)\n| 2. PEM format\n| 3. Return")
        try:
            choice = int(input("Type the number to select your answer: "))
            if choice in [1,2]:
                start = time.perf_counter()
                e,d,n,p,q = rsa.rsa_generate_keys(choice)
                end = time.perf_counter()
                
                print()
                store_key(n,e,'pub',choice,1)
                store_key(n,d,'priv',choice,p,q)
                return (end - start) * 1000
        except ValueError:
            pass
        

"""
Signs document with given private key
"""
def sign(file_path,priv_path) -> tuple[float,float]: 
    with open(file_path,'rb') as f:
        data = f.read()
       
    n, d = get_keys(priv_path)

    
    start = time.perf_counter()
    encoded_message = pss.pss_encode(data)
    end = time.perf_counter()
    pss_encoding_time = (end - start) * 1000
    
    start = time.perf_counter()
    signed_message = rsa.rsa_sign(int.from_bytes(encoded_message), n, d)
    end = time.perf_counter()
    signature_time = (end - start) * 1000

    sig_path = file_path + ".sig"
    with open(sig_path, "wb") as sig_file:
        sig_file.write(base64.b64encode(int_to_bytes(signed_message)))
    
    print(f"| File signed successfully, stored as {os.path.basename(sig_path)}")
    return (pss_encoding_time,signature_time)

"""
With a given document, signature and public key, checks if signature is valid for said document
"""
def verify(file_path,sig_path,pub_path) -> bool:
    with open(file_path,'rb') as f:
        data = f.read()
       
    n, e = get_keys(pub_path)
    
    with open(sig_path, "r") as s:
        signature_b64 = s.read()

    signature_bytes = base64.b64decode(signature_b64)
    signature_int = int.from_bytes(signature_bytes, 'big')

    
    start = time.perf_counter()
    verified_message = rsa.rsa_verify(signature_int, n, e)
    end = time.perf_counter()
    rsa_verify_time = (end - start) * 1000

    start = time.perf_counter()
    result = pss.pss_verify(data, int_to_bytes(verified_message))
    end = time.perf_counter()
    pss_decode_time = (end - start) * 1000
    
    return (result, rsa_verify_time,pss_decode_time)


"""
HELPER FUNCTIONS
"""
# Converts int to bytes
def int_to_bytes(i : int) -> bytes:
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, byteorder="big")

# Stores given key in correct directory
def store_key(n:int,key:int,type='pub', choice = 1, p = None, q = None):
    now = datetime.now()
    now = now.strftime("%Y%m%d_%H%M%S")

    current_path = os.path.dirname(os.path.abspath(__file__))
    project_path = os.path.abspath(os.path.join(current_path, ".."))

    key_folder = os.path.abspath(os.path.join(project_path, "pub")) if type == 'pub' else os.path.abspath(os.path.join(project_path, "priv"))

    match choice:
        case 1:
            if TEST_FLAG:
                key_name = 'test-pub.custom_key' if type == 'pub' else 'test-priv.custom_key'
            else:
                key_name = f'{now + '-pub.custom_key'}' if type == 'pub' else f'{now + "-priv.custom_key"}'
            key_path = os.path.join(key_folder, key_name) if type == 'pub' else os.path.join(key_folder, key_name)

            if not os.path.exists(key_folder):
                os.makedirs(key_folder)

            ser = "---- BEGIN PUBLIC KEY ----" if type == 'pub' else "---- BEGIN PRIVATE KEY ----"
            ser += f'\nmodulus: {base64.b64encode(int_to_bytes(n)).decode()}\n'
            ser += f'key: {base64.b64encode(int_to_bytes(key)).decode()}\n'
            ser += "---- END PUBLIC KEY ----" if type == 'pub' else "---- END PRIVATE KEY ----"
            with open(key_path, "w") as f:
                f.write(ser)

            print(f"| {'Public' if type == 'pub' else 'Private'} key stored successfully as {key_name} on the {type} directory")
            return
        case _: pass

    if TEST_FLAG:
        key_name = 'test-pub.pem' if type == 'pub' else 'test-priv.pem'
    else:
        key_name = f'{now + '-pub.pem'}' if type == 'pub' else f'{now + "-priv.pem"}'
    key_path = os.path.join(key_folder, key_name) if type == 'pub' else os.path.join(key_folder, key_name)

    if not os.path.exists(key_folder):
        os.makedirs(key_folder)

    if type == 'priv':
        # Using cryptography's library to serialize into PEM
        if p is None or q is None:
            raise ValueError("To store a private key, p and q must be provided")

        dmp1 = key % (p - 1)
        dmq1 = key % (q - 1)
        iqmp = pow(q, -1, p)

        private_numbers = rsaModule.RSAPrivateNumbers(
            p=p,
            q=q,
            d=key,
            dmp1=dmp1,
            dmq1=dmq1,
            iqmp=iqmp,
            public_numbers=rsaModule.RSAPublicNumbers(e=65537, n=n)
        )

        private_key = private_numbers.private_key(default_backend())

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,  # or PKCS8
            encryption_algorithm=serialization.NoEncryption()  # Or use BestAvailableEncryption(b"password")
        )

    else:
        public_numbers = rsaModule.RSAPublicNumbers(e=key, n=n)
        public_key = public_numbers.public_key(default_backend())

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    with open(key_path, "wb") as f:
        f.write(pem)

    print(f"| {'Public' if type == 'pub' else 'Private'} key stored successfully as {key_name} in the {type} directory")


# Gets the key from a given key file and returns it as an int tuple
def get_keys(key_path) -> tuple[int,int]:
    if key_path.endswith(".pem"):
        with open(key_path, "rb") as f:
            key_data = f.read()

        try:
            key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )
            numbers = key.private_numbers()
            return (numbers.public_numbers.n, numbers.d)
        except ValueError:
            key = serialization.load_pem_public_key(
                key_data,
                backend=default_backend()
            )
            numbers = key.public_numbers()
            return (numbers.n, numbers.e)
    
    else: # Assumes it's a .custom_key
        with open(key_path, "r") as f:
            key_str = f.read()
        
        for line in key_str.split('\n'):
            if "modulus" in line:
                b64_modulus = line[len("modulus: "):]
                n = int.from_bytes(base64.b64decode(b64_modulus), 'big') 
            if "key" in line:
                b64_key = line[len("key: "):]
                key = int.from_bytes(base64.b64decode(b64_key), 'big') 
        
        return (n,key)