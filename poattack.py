from paddingoracle import PaddingOracle, xor
import os

def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]

def po_attack_2blocks(po, ctx):
    """Given two blocks of cipher texts, it can recover the first block of
    the message.
    @po: an instance of padding oracle.
    @ctx: a ciphertext generated using po.setup()
    Don't unpad the message.
    """
    assert len(ctx) == 2*po.block_length, "This function only accepts 2 block "\
        "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)
    c0, c1 = list(split_into_blocks(ctx, po.block_length))
    msg = ''

    # Implementation of the procedure described in the following paper
    # https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf

    last_bytes = _po_attack_last_bytes(po, c0, c1)
    last_bytes = list(last_bytes)


    while len(last_bytes) < len(c1):
        j = len(c0) - len(last_bytes)

        # STEP 1 and 2
        r = list(os.urandom(len(c0[:j]))) + last_bytes
        for k in range(j, len(c0)):
            r[k] = chr(ord(r[k]) ^ (len(r)-1-j+2))

        i = 0
        while True:
            assert i < 256
            r_ = r[:]
            r_[j-1] = chr(ord(r_[j-1]) ^ i)
            if po.decrypt(c0 + ''.join(r_)+c1):
                break
            i += 1
        print i,

        res = chr(ord(r[j-1]) ^ i ^ (len(r) - 1 - j + 2))
        last_bytes.insert(0, res)
    print

    msg = ''.join(last_bytes)
    print(len(msg))
    return msg

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle.
    @ctx: a ciphertext generated using po.setup()
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)
    # TODO: Implement padding oracle attack for arbitrary length message.
    msg = ''
    for i in range(nblocks-1):
        blocks_of_2 = ctx_blocks[i] + ctx_blocks[i+1]
        curr_msg = po_attack_2blocks(po, blocks_of_2)
    return msg

def _po_attack_last_bytes(po, c0_, c1):

    c0 = os.urandom(len(c0_))
    # STEP 1
    # random bytes are the IV = c0
    i = 0

    while True:
        assert i < 256

        # STEP 2
        r = c0[:-1] + chr(ord(c0[-1])^i)

        # STEP 3
        if po.decrypt(r+c1):
            print("Here")
            break
        i += 1
    print(i)
    # STEP 4
    c0 = list(c0)
    c0[-1] = chr(ord(c0[-1]) ^ i)

    ###### c0 is list of bytes #######
    for n in range(len(c0)-1, 0, -1):
        idx = len(c0)-n-1
        r = c0[:]
        r[idx] = chr(ord(r[idx]) ^ 1)
        if not po.decrypt(c0_ + ''.join(r)+c1):
            print("here2")
            return _xor_last_bytes(c0, idx, n)[-idx:]
    return chr(ord(c0[-1]) ^ 1)

def _integer_to_bytes(integer):
    to_hex = "{0:032x}".format(integer)
    to_bytes = to_hex.decode('hex')
    return to_bytes

def _xor_last_bytes(c0, start, n):
    for i in range(start, len(c0)):
        c0[i] = chr(ord(c0[i]) ^ n)
    return c0

################################################################################
##### Tests
################################################################################

def test_po_attack_2blocks():
    for i in xrange(1, 16):
        po = PaddingOracle(msg_len=i)
        ctx = po.setup()
        msg = po_attack_2blocks(po, ctx)
        assert po.test(msg), "Failed 'po_attack_2blocks' for msg of length={}".format(i)

def test_po_attack():
    for i in xrange(1000):
        po = PaddingOracle(msg_len=i)
        ctx = po.setup()
        msg = po_attack(po, ctx)
        assert po.test(msg), "Failed 'po_attack' for msg of length={}".format(i)

if __name__ == "__main__":
    test_po_attack_2blocks()
