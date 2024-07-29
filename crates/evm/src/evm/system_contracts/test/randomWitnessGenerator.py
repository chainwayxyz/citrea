import random

def random_hex_byte(l, r):
    assert(l >= 0)
    assert(r <= 255)
    # Generate a random integer between l and r
    random_int = random.randint(l, r)
    # Convert the integer to a hexadecimal string and remove the '0x' prefix
    hex_value = hex(random_int)[2:]
    # Ensure the hex value has two digits
    if len(hex_value) == 1:
        hex_value = '0' + hex_value
    return hex_value

witness = ""
nStackItems = random_hex_byte(0, 8)
witness += nStackItems
for k in range(int(nStackItems, 16)):
    stackItemLength = random_hex_byte(0, 16)
    witness += stackItemLength
    for m in range(int(stackItemLength, 16)):
        randombyte = random_hex_byte(0, 255)
        witness += randombyte
print(witness)





