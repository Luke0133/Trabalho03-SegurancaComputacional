from helpers import pss
from helpers import rsa
import base64, os, time
from datetime import datetime

TEST_FLAG = False

"""
Generates and stores Keys (and returns time elapsed during key generation)
"""
def generate_keys() -> float:
    start = time.perf_counter()
    e,d,n = rsa.rsa_generate_keys()
    end = time.perf_counter()
    
    store_key(n,e,'pub')
    store_key(n,d,'priv')
    return (end - start) * 1000

"""
Signs document with given private key
"""
def sign(file_path,priv_path) -> None: 
    with open(file_path,'rb') as f:
        data = f.read()
       
    n, d = get_keys(priv_path)

    encoded_message = pss.pss_encode(data)

    signed_message = rsa.rsa_sign(int.from_bytes(encoded_message), n, d)

    sig_path = file_path + ".sig"
    with open(sig_path, "wb") as sig_file:
        sig_file.write(base64.b64encode(int_to_bytes(signed_message)))
    
    print(f"File signed successfully, stored as {os.path.basename(sig_path)}")
    return

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

    verified_message = rsa.rsa_verify(signature_int, n, e)

    return pss.pss_verify(data, int_to_bytes(verified_message))


"""
HELPER FUNCTIONS
"""
# Converts int to bytes
def int_to_bytes(i : int) -> bytes:
    length = (i.bit_length() + 7) // 8
    return i.to_bytes(length, byteorder="big")

# Stores given key in correct directory
def store_key(n:int,key:int,type='pub'):
    now = datetime.now()
    now = now.strftime("%Y%m%d_%H%M%S")

    current_path = os.path.dirname(os.path.abspath(__file__))
    project_path = os.path.abspath(os.path.join(current_path, ".."))

    key_folder = os.path.abspath(os.path.join(project_path, "pub")) if type == 'pub' else os.path.abspath(os.path.join(project_path, "priv"))
    if TEST_FLAG:
        key_name = 'test-pub.key' if type == 'pub' else 'test-priv.key'
    else:
        key_name = f'{now + '-pub.key'}' if type == 'pub' else f'{now + "-priv.key"}'
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

# Gets the key from a given key file and returns it as an int tuple
def get_keys(key_path) -> tuple[int,int]:
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