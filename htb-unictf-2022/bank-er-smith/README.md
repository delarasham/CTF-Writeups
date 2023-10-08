# Bank-er Smith

## Description
You used the invisibility cloak to enter the bank and spy on the employees. They seem to be using magic to automate the paperwork. As you watched the papers flying around, you managed to steal one of them. It contains details about the vault containing the Golden Grail with Valdemort's soul. After regrouping with Ermiani and Ran, you drank the transformation poison and entered the bank as one of the employees. The passphrase for the vault is encrypted, and the only thing you can ask the bank for is a small hint that seems to be magic-proof.

## Files 
### server.py
```python
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse, GCD
from secret import FLAG, KEY

WELCOME = """
************** Welcome to the Gringatts Bank. **************
*                                                          *
*                  Fortius Quo Fidelius                    *
*                                                          *
************************************************************
"""


class RSA():

    def __init__(self, key_length):
        self.e = 0x10001
        phi = 0
        prime_length = key_length // 2

        while GCD(self.e, phi) != 1:
            self.p, self.q = getPrime(prime_length), getPrime(prime_length)
            phi = (self.p - 1) * (self.q - 1)
            self.n = self.p * self.q

        self.d = inverse(self.e, phi)

    def encrypt(self, message):
        message = bytes_to_long(message)
        return pow(message, self.e, self.n)

    def decrypt(self, encrypted_message):
        message = pow(encrypted_message, self.d, self.n)
        return long_to_bytes(message)


class Bank:

    def __init__(self, rsa):
        self.options = "[1] Get public certificate.\n[2] Calculate Hint.\n[3] Unlock Vault.\n"
        self.shift = 256
        self.vaults = {
            f"vault_{i}": [b"passphrase", b"empty"]
            for i in range(100)
        }
        self.rsa = rsa

    def initializeVault(self, name, passphrase, data):
        self.vaults[name][0] = passphrase
        self.vaults[name][1] = data

    def calculateHint(self):
        return (self.rsa.p >> self.shift) << self.shift

    def enterVault(self, vault, passphrase):
        vault = self.vaults[vault]
        if passphrase.encode() == vault[0]:
            return vault[1].decode()
        else:
            print("\nFailed to open the vault!\n")
            exit(1)


if __name__ == "__main__":
    rsa = RSA(2048)
    bank = Bank(rsa)

    vault = "vault_68"
    passphrase = KEY
    bank.initializeVault(vault, passphrase, FLAG)

    encrypted_passphrase = rsa.encrypt(bank.vaults[vault][0])
    print(f"You managed to retrieve: {hex(encrypted_passphrase)[2:]}")
    print("\nNow you are ready to enter the bank.")
    print(WELCOME)

    while True:
        try:
            print("Hello, what would you like to do?\n")
            print(bank.options)
            option = int(input("> "))

            if option == 1:
                print(f"\n{bank.rsa.n}\n{bank.rsa.e}\n")
            elif option == 2:
                print(f"\n{bank.calculateHint()}\n")
            elif option == 3:
                vault = input("\nWhich vault would you like to open: ")
                passphrase = input("Enter the passphrase: ")
                print(f"\n{bank.enterVault(vault, passphrase)}\n")
            else:
                "Abort mission!"
                exit(1)
        except KeyboardInterrupt:
            print("Exiting")
            exit(1)
        except Exception as e:
            print(f"An error occurred while processing data: {e}")
            exit(1)
```
## Solve

First I looked through google trying to figure out how to break RSA when some part of p is known. I stumbled upon a research paper that mentioned coppersmith's primes. Checking with the name of the challenge I was sure I was on the right path. After researching some more I got to this page https://latticehacks.cr.yp.to/rsa.html which has an explanation of how to find p when some part of it is known. So I used their `sage` script with the numbers given from connecting to the box to get to `p`. After that I reverse engineered `d` which then gave me the passphrase by decrypting the hex given. Given the passphrase `The_horcrux_is_Helga_Hufflepuff's_cup` I was able to open the vault 68 and get the flag. 

## Exploit
### sage script 
```python
## reference https://latticehacks.cr.yp.to/rsa.html
## shoutout to them for this script
class partial_factoring:
    def __init__(self,N,a,X):
        self.N = N
        self.a = a
        self.X = X
        self.R = ZZ['x']
        x = self.R.0
        self.f = x+a
    # k is the multiplicity of the desired roots mod N
    # kd+t-1 is the degree of the polynomial that is produced
    def gen_lattice(self,t=1,k=1):
        dim = k+t
        A = matrix(IntegerRing(),dim,dim)
        x = self.R.0
        X = self.X

        monomial_list = [x^i for i in range(dim)]
        for i in range(k):
            g = self.f(X*x)^i*self.N^(k-i)
            A[i] = [g.monomial_coefficient(mon) for mon in monomial_list]
        for j in range(t):
            g = self.f(X*x)^k*(X*x)^j
            A[k+j] = [g.monomial_coefficient(mon) for mon in monomial_list]

        weights = [X^i for i in range(dim)]
        def getf(M,i):
            return sum(self.R(b/w)*mon for b,mon,w in zip(M[i],monomial_list,weights))
        return A,getf

    def solve(self,t=1,k=1):
        A,getf = self.gen_lattice(t,k)
        B = A.LLL()
        factors = []
        for r,multiplicity in getf(B,0).roots():
            if r not in ZZ:
                continue
            if gcd(Integer(self.f(r)),self.N) != 1:
                p = gcd(self.f(r),self.N)
                factors.append(p)
        return factors

def factoring(N,a):
    X = 2^256
    u = partial_factoring(N,a,X)
    p=u.solve(2,1)[0]
```
### python script
```python
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse, GCD

N= 17304033622962561310389831642486174681999608271488154878666291470490691871726487127704484465049459680463404462283250382310537000623347003893670134880051807947502628079278216261738961032628386035432728579622953972616117453991192600198168327961917252001620550080302029984615376497800960340871275096770110238582152649712683655677691917656774975241324091222655338285590704388090955204640867921005273927504202700095310247175505865041082899275864607509908305019410083776012406600548153127258630512552372235810349785376762164262392147806909165311292157303431567954521538253159252687371001250757425372589430673397207617199649
p = <sage-output>
q = N/p
phi = (p-1) * (q-1)
d = pow(e,-1,phi)
encrypted_passphrase = b'0x85ebb11acddff45f65e11b8e26811eb13b884146b89c57c2ec55fa15ae4b65b2e7717e37f56d5cd8e15179bf463bb13cabfe3caf12a710832cdd13b5797f6587a7e0a057e0616a583b5b04062ed812ae9a4d5259c380f87c1515302935eddc4d3ca4c7f0db5293a5ff05b91b751170fded9071af48cc2e314ac90b9cead91a7fdd53510ced1d3333afd47e10c1170fdf3ce63e3e7dfed45c72d5fb007be9fa7875cd6369b17fbffcc610e6fb8d65a889c0f0e019d158dc32d659df219a63340835e69465bf0c82d313a7e1ba9ada90b091624938a7f45a5ef50b70c477f1cf79b4831a60cc853c3e4a752f36ee852f4808c75c9997b589cbc5789f9e27f8c04'
en = int(encrypted_passphrase,0)
passphrase = pow(en,d,N)
print(long_to_bytes(passphrase).decode())
```

## Flag 
`HTB{LLL_4nd_c00p325m17h_15_57111_m491c_70_my_3y35}`
