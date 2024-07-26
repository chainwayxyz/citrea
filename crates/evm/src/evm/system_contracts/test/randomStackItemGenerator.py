import random

def random_hex_byte(l, r):
    # Generate a random integer between l and r
    random_int = random.randint(l, r)
    # Convert the integer to a hexadecimal string and remove the '0x' prefix
    hex_value = hex(random_int)[2:]
    # Ensure the hex value has two digits
    if len(hex_value) == 1:
        hex_value = '0' + hex_value
    return hex_value

stackItem = ""
stackItemLength = random_hex_byte(0, 16)
stackItem += stackItemLength
for m in range(int(stackItemLength, 16)):
    randombyte = random_hex_byte(0, 255)
    stackItem += randombyte
print(stackItem)





