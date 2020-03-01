import hmac

# The block size = 2 * hash digest length
BLK_SIZE = 32

def xor(a, b):
    """Implement xor for 2 bytearrays.

    Arguments:
        a (bytearray): First byte array.
        b (bytearray): Second byte array.
    
    Returns:
        bytearray: The result of a XOR b.
    
    """
    return bytearray([ai ^ bi for (ai, bi) in zip(a, b)])

def round(data, F):
    """Defines one round of Fiestel cipher on the bytearray ``data``
    using the function ``F``.

    Arguments:
        data (bytearray): data in the form of bytearray.
        F (callable): A function that will be used in the fiestel cipher.

    Returns:
        bytearray: returns the data after the current round of the cipher.
    
    """
    L = len(data)
    if L & 1:
        raise Exception("Invalid data size: {}".format(L))
    
    left, right = data[:L//2], data[L//2:]

    return right + xor(left, F(right))

def hash_func(data):
    """A sample hash function with a static key.

    Arguments:
        data (bytearray): The data to hash.
    
    Returns:
        bytearray: The hash of the data.
    
    """
    h = hmac.new(b'secret key')
    h.update(data)
    return bytearray(h.digest())

def flip(data):
    """Flip the data according to fiestel flip. This means that 
    the first and second halves were exchanged.

    Arguments:
        data (bytearray): The data to flip.
    
    Returns:
        bytearray: The flipped data bytearray.
    """
    l = len(data)
    return data[l//2:] + data[:l//2]

def pad(data):
    """Pad the data bytearray with the block size of BLK_SIZE using
    the PKCS#7 format.

    Arguments:
        data (bytearray): The data to be padded.
    
    Returns:
        bytearray: Return the padded bytearray.
    """
    m = BLK_SIZE - len(data) % BLK_SIZE
    return data + bytearray([m] * m)

def unpad(data):
    """Unpad the PKCS#7 data with BLK_SIZE block size.

    Arguments:
        data (bytearray): Padded bytearray.

    Returns:
        bytearray: Return unpadded bytearray.
    """
    if len(data) == 0:
        return data
    
    return data[:-data[-1]]

def crypt(data, F, decrypt=False, r = 32):
    """Encrypt or decrypt a piece of data using the fiestel cipher and
    the hash function F.

    Arguments:
        data (bytearray): The data to encrypt.
        F (callable): A hash function that outputs 16 bytes of digest.
        decrypt (boolean): If the operation is decryption or not.
        r (int): The number of fiestel cycles.
    
    Returs:
        bytearray: Encrypted or decrypted data based on flags.
    """
    data = data if decrypt else pad(data)
    blks = [
        data[i: i + BLK_SIZE] for i in range(0, len(data), BLK_SIZE)
    ]

    res = bytearray()
    for blk in blks:
        for _ in range (r):
            blk = round(blk, F)
        res = res + flip(blk)

    return unpad(res) if decrypt else res

if __name__ == '__main__':
    d = bytearray("hello world with fiestel cipher but it would like to do something that no one has done before", "utf-8")
    e = crypt(d, hash_func)
    print (e)

    e = crypt(e, hash_func, True)
    print (e)