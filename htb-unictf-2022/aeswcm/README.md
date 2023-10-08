# AESWCM

## Description
Few people on this planet studied wandlore. It was known that the wand selects the wizard, but a good wand seller should be able to guess it with at most 3 suggestions. During the 190th Great Wizard Examination, the last question was created by Olivender, the greatest wand seller of all time. It was considered one of the most difficult questions of the last decade. Can you solve it?

## Files
### Server.py
```python
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
import os
import random
from secret import FLAG

KEY = os.urandom(16)
IV = os.urandom(16)


class AESWCM:

    def __init__(self, key):
        self.key = key
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.BLOCK_SIZE = 16

    def pad(self, pt):
        if len(pt) % self.BLOCK_SIZE != 0:
            pt = pad(pt, self.BLOCK_SIZE)
        return pt

    def blockify(self, message):
        return [
            message[i:i + self.BLOCK_SIZE]
            for i in range(0, len(message), self.BLOCK_SIZE)
        ]

    def xor(self, a, b):
        return bytes([aa ^ bb for aa, bb in zip(a, b)])

    def encrypt(self, pt, iv):
        pt = self.pad(pt)
        blocks = self.blockify(pt)
        xor_block = iv

        ct = []
        for block in blocks:
            ct_block = self.cipher.encrypt(self.xor(block, xor_block))
            xor_block = self.xor(block, ct_block)
            ct.append(ct_block)

        return b"".join(ct).hex()

    def decrypt(self, ct, iv):
        ct = bytes.fromhex(ct)
        blocks = self.blockify(ct)
        xor_block = iv

        pt = []
        for block in blocks:
            pt_block = self.xor(self.cipher.decrypt(block), xor_block)
            xor_block = self.xor(block, pt_block)
            pt.append(pt_block)

        return b"".join(pt)

    def tag(self, pt, iv=os.urandom(16)):
        blocks = self.blockify(bytes.fromhex(self.encrypt(pt, iv)))
        random.shuffle(blocks)

        ct = blocks[0]
        for i in range(1, len(blocks)):
            ct = self.xor(blocks[i], ct)

        return ct.hex()


def main():
    aes = AESWCM(KEY)
    tags = []
    characteristics = []
    print("What properties should your magic wand have?")
    message = "Property: "

    counter = 0
    while counter < 3:
        characteristic = bytes.fromhex(input(message))
        if characteristic not in characteristics:
            characteristics.append(characteristic)

            characteristic_tag = aes.tag(message.encode() + characteristic, IV)
            tags.append(characteristic_tag)
            print(characteristic_tag)

            if len(tags) > len(set(tags)):
                print(FLAG)

            counter += 1
        else:
            print("Only different properties are allowed!")
            exit(1)


if __name__ == "__main__":
    main()
```
## Solve

Looking through the source is the line that gives us the flag : 

```python
if len(tags) > len(set(tags)):
   print(FLAG)
```

This means we have to give them two or more numbers that give out the same tag back and that's how we can get to that if statement and get the flag. 

After some tests, I realized if you give it a string with length 12 like `111111111111` the pt is going to be just one block and so the tag that it gives back is going to be the ct. The iv is not really used in the tag functions which is the only way we can decrypt something so I don't think we need to go down the decryption route. Next I looked at the padding scheme. The program seems to be padding a string only if the size is more that 16 bytes and not a multiple of it. So it doesn't pad anything that's 12 bytes. Now the padding scheme PKCS7 essentially add the number that needs to be padded to the string to pad it. So if a string needs 6 bytes of pad, it pads 6 to the string 6 times. https://www.ibm.com/docs/en/zos/2.4.0?topic=rules-pkcs-padding-method
With this we can essentially find two strings that have the same tag by crafting one string that doesn't need a pad and one that when padded with be the same as the first string. One such pair that I found was `111111111101` and `1111111111` 

## Exploit
```bash
$ nc 167.99.206.87 32328
What properties should your magic wand have?
Property: 111111111101
3bb1c0b9d5426ebaea0ad431a7cedc5a
Property: 1111111111
3bb1c0b9d5426ebaea0ad431a7cedc5a
HTB{435_cu570m_m0d35_4nd_hm4c_423_fun!}
```

## Flag
`HTB{435_cu570m_m0d35_4nd_hm4c_423_fun!}`