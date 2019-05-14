import base58check
import hashlib
from pycoin import key


wallet = '1HammaXcmybjPK4yLJxWkCrYQHd3fyLcU7'

# WIP key with random last 8 symbols
wip_fake = '5JRd42nU1gL5wuDRgVRRTCdHRAhiF1tpuGfy2nm3YtN11111111'
# Convert fake WIP key to the real secret key with checksum
wipd_fake = base58check.b58decode(wip_fake)
# Trim last 6 bytes (2 last bytes from secret key + checksum)
wipd_fake_starting = wipd_fake[:-6]

print(f'WIP fake  : {wip_fake}')
print(f'WIPd full : {wipd_fake.hex().upper()}')
print(f'WIPd trim : {wipd_fake_starting.hex().upper()}\n')

# Generate list of random bytes 00..FF
bb = [bytes([b]) for b in range(256)]
c = -1
exit(0)
for i in bb:
    for j in bb:
        c += 1
        # Add 2 random bytes to the secret key starting
        wipd_test = wipd_fake_starting + i + j

        # Calc SHA256(WIPd)
        h = hashlib.sha256()
        h.update(wipd_test)
        wipd_sha256 = h.digest()

        # Calc SHA256(SHA256(WIPd))
        h = hashlib.sha256()
        h.update(wipd_sha256)
        wipd_sha256x2 = h.digest()

        # Get checksum (first 4 bytes from hash)
        checksum = wipd_sha256x2[:4]
        # Concat WIPd and checksum
        wip_key = base58check.b58encode(wipd_test+checksum)
        # Generate wallet address
        k = key.Key.from_text(wip_key.decode())

        if c % 1024 == 0:
            print(f'{c:5} keys checked...')
        if wallet == k.address():
            print(f'{c:5} GOTCHA! {wallet} == {k.address()}')
            print(f'WIP key: {wip_key.decode()}')
            exit(0)
