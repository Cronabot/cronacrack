import argparse, hashlib
from itertools import product

#Characters to use when brute forcing
chars = "abcdefghijklmnopqrstuvwxyz"#ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def crack(args):
    h = args.hash
    prnt = args.shouldPrint
    #Check if salt exists. If not, just set to an empty string
    if args.salt:
        s = args.salt
    else:
        s=''
    
    cracked = False

    if args.fLength:
        if args.fLength <= 0: # Validate fixed length
            print("Length of password must be more than 0")
            return
    
    if args.charLim:
        if args.charLim <= 0: # Validate character limit
            print("Character limit must be more than 0")
            return

    #Check the specified hashing algorithm exists in hashlib
    try:
        hashingAlgorithm = getattr(hashlib, args.method)
    except:
        print("Invalid hashing algorithm specified!")
        return

    print(f'Cracking hash using {args.method}')

    #Crack using a password list
    if args.passwordList != None:
        print("Password list specified! Attempting passwords...")
        passList = []
        with open(args.passwordList, 'r', encoding="utf8", errors='ignore') as passFile:
            print('Reading password file...')
            for password in passFile.readlines(): #Generate array containing all passwords in the password list
                if args.fLength:
                    if args.fLength == len(password.strip()):
                        passList.append(password.strip())
        
        print('Checking passwords...')

        for password in passList:
            if cracked:
                break
            saltedPass = s + password #Add the salt to the attempt password
            hashedPass = hashingAlgorithm(saltedPass.encode()).hexdigest() #Hash the attempt password
            if h == hashedPass:
                print('==+==+==+==+==+==+==+==+==+==')
                print(password)
                print('==+==+==+==+==+==+==+==+==+==')
                cracked = True
                continue
            if prnt:
                print(password) #Print out failed attempt if enabled
            
    else: #Crack using brute force
        print("Password list not specified! Brute forcing...")

        limit = 6
        if args.charLim:
            limit = args.charLim

        for length in range(limit+1):
            if args.fLength:
                length = args.fLength
            toAttempt = product(chars, repeat=length) #Generate list of possible character combinations at length "length"
            for a in toAttempt:
                aSalted = s + ''.join(a) #Add the salt to the attempt
                if hashingAlgorithm(aSalted.encode()).hexdigest() == h:
                    print('==+==+==+==+==+==+==+==+==+==')
                    print(''.join(a))
                    print('==+==+==+==+==+==+==+==+==+==')
                    cracked = True
                    break
                if prnt:
                    print(''.join(a)) #Print out failed attempt if enabled
            if cracked:
                break
            if args.fLength:
                break

    if not cracked:
        print("Password could not be cracked")

#Initiate the program
def main():
    #Set up the argument parser with args
    parser = argparse.ArgumentParser(description="A hash cracking tool written in python")
    parser.add_argument("-hash", help="The hash to crack", dest="hash", type=str, required=True)
    parser.add_argument("-salt", help="The salt that comes with the password", dest="salt", type=str, required=False)
    parser.add_argument("-method", help="The hashing algorithm you would like to use", dest="method", type=str, required=True)
    parser.add_argument("-passL", help="The password list you would like to use", dest="passwordList", type=str, required=False)
    parser.add_argument("-length", help="Only attempts passwords of a fixed length", dest="fLength", type=int, required=False)
    parser.add_argument("-charLimit", help="Define a new limit of characters to bruteforce", dest="charLim", type=int, required=False)
    parser.add_argument("-print", help="Whether you want to print out each attempt", dest="shouldPrint", type=bool, required=False)
    parser.set_defaults(func=crack)
    args = parser.parse_args()
    
    args.func(args) #Execute crack() with args

#Check the file is being run directly and not being imported
if __name__=="__main__":
    main()