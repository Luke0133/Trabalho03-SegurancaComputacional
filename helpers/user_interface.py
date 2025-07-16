from helpers import rsa
from helpers import operations as op
import os
from time import sleep

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def main_ui():
    while True:
        clear_screen()
        print("Signature Generator and Verifier -- Developed by Eduardo Pereira and Luca Megiorin")
        print("Choose an option:\n| 1. Generate Keys\n| 2. Sign/Verify\n| 3. Exit")
        try:
            choice = int(input("Type the number to select your answer: "))
            if choice in [1, 2, 3]:
                return choice
        except ValueError:
            pass

def ui_generate_keys():
    while True:
        clear_screen()
        print("Signature Generator and Verifier: Key Generation")
        print("Choose an option:\n| 1. Normal generation (Uses a set of 500 primes before Miller-Rabin)\n| 2. Choose pre-calculated primes list length\n| 3. Return")
        try:
            choice = int(input("Type the number to select your answer: "))
            match choice:
                case 1:
                    op.N_PRIMES = 500
                    break
                case 2:
                    while True:
                        clear_screen()
                        print("Signature Generator and Verifier: Key Generation")
                        print("Choose an option:\n| 1. Normal generation (Uses a set of 500 primes before Miller-Rabin)\n| 2. Choose pre-calculated primes list length\n| 3. Return")
                        try:
                            print("Type the number to select your answer: 2")
                            n = int(input("Choose between 0 and 1000 prime numbers (input 0 to only use Miller-Rabin): "))
                            
                            if n >= 0 and n <= 1000: 
                                op.N_PRIMES = n
                                break
                        except ValueError:
                            pass
                    break
                case 3: return
                case _: pass
        except ValueError:
            pass
            
    print()
    time_elapsed = op.generate_keys()
    print(f"\nTime Elapsed During Key Generation: {time_elapsed:.4f} ms")
    sleep(1)
    input("\nPress ENTER to continue")
    return
    

def ui_sign_verify():
    while True:
        clear_screen()
        print("Signature Generator and Verifier: Sign and Verify")
        print("Choose an option:\n| 1. Sign File\n| 2. Verify Signature\n| 3. Return")
        try:
            choice = int(input("Type the number to select your answer: "))
            match choice:
                case 1:
                    err = None
                    while True:
                        clear_screen()
                        print("Signature Generator and Verifier: Key Generation - Sign File")
                        if err: print(err)
                        file_path = input("Path to your file: ")
                        if not os.path.isfile(file_path): err = "Invalid path"
                        else: break
                    
                    err = None
                    while True:
                        clear_screen()
                        print("Signature Generator and Verifier: Key Generation - Sign File")
                        print(f"Path to your file: {file_path}")
                        if err: print(err)
                        priv_path = input("Path to your private .key file: ")
                        if not os.path.isfile(priv_path): err = "Invalid path"
                        else: break

                    
                    print()
                    pss_encoding_time,signature_time = op.sign(file_path,priv_path)
                    print(f"\nTime Elapsed During PSS Encoding: {pss_encoding_time:.4f} ms")
                    print(f"\nTime Elapsed During RSA signing: {signature_time:.4f} ms")
                    sleep(1)
                    input("\nPress ENTER to continue")
                    

                case 2:
                    err = None
                    while True:
                        clear_screen()
                        print("Signature Generator and Verifier: Key Generation - Verify Signed File")
                        if err: print(err)
                        file_path = input("Path to your file: ")
                        if not os.path.isfile(file_path): err = "Invalid path"
                        else: break
                    
                    err = None
                    while True:
                        clear_screen()
                        print("Signature Generator and Verifier: Key Generation - Verify Signed File")
                        print(f"Path to your file: {file_path}")
                        if err: print(err)
                        sig_path = input("Path to your .sig file: ")
                        if not os.path.isfile(sig_path): err = "Invalid path"
                        else: break

                    
                    err = None
                    while True:
                        clear_screen()
                        print("Signature Generator and Verifier: Key Generation - Verify Signed File")
                        print(f"Path to your file: {file_path}")
                        print(f"Path to your .sig file: {file_path}")
                        if err: print(err)
                        pub_path = input("Path to your public .key file: ")
                        if not os.path.isfile(pub_path): err = "Invalid path"
                        else: break

                    
                    print()
                    check,rsa_verify_time,pss_decode_time = op.verify(file_path,sig_path,pub_path)
                    if check: print("| Valid signature")
                    else: print("| Invalid signature")
                    print(f"\nTime Elapsed During RSA Decrypting: {rsa_verify_time:.4f} ms")
                    print(f"Time Elapsed During PSS Verification: {pss_decode_time:.4f} ms")
                    sleep(1)
                    input("\nPress ENTER to continue")

                case 3: return
                case _: pass
        except ValueError:
            pass




if __name__ == "__main__":
    op.N_PRIMES = 1000

    file_path = input("File: ")
    with open(file_path,'rb') as f:
        data = f.read()
    
    op.TEST_FLAG = True
    op.generate_keys()
    op.TEST_FLAG = False

    rsa.sign(file_path,"priv/test-priv.key")
    result = rsa.verify(file_path,file_path + ".sig","pub/test-pub.key")

    
    if result: print("Valid Signature")
    else: print("Invalid Signature")