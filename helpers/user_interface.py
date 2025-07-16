from helpers import rsa
from helpers import operations as op
import os

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
        print("Choose an option:\n| 1. Normal generation (Uses a set of 500 primes before Miller-Rabin)\n| 2. Choose pre-calculated primes list length\n| 3. Exit")
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
                        print("Choose an option:\n| 1. Normal generation (Uses a set of 500 primes before Miller-Rabin)\n| 2. Choose pre-calculated primes list length\n| 3. Exit")
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
    input("\nPress ENTER to continue")
    return
    

def ui_sign_verify():
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