#!/usr/bin/python3

# Data grabbed from < https://blockchain.info/block-height/125552?format=json >

from hashlib import sha256

def to_var_int(n):
    if n < 0xfd:
    	return n.to_bytes(1, 'little')
    if n <= 0xffff:
        return b'\xfd' + n.to_bytes(2, 'little')
    if n <= 0xffffffff:
        return b'\xfe' + n.to_bytes(4, 'little')
    return b'\xff' + n.to_bytes(8, 'little')

def process_tx():
    m = bytearray()
    m.extend(version.to_bytes(4, 'little'))
    m.extend(to_var_int(len(tx_in)))
    for (prevTxHash, prevTxNo), script, sequence in tx_in:
        script = bytes.fromhex(script)
        m.extend(bytes.fromhex(prevTxHash)[::-1])
        m.extend(prevTxNo.to_bytes(4, 'little'))
        m.extend(to_var_int(len(script)))
        m.extend(script)
        m.extend(sequence.to_bytes(4, 'little'))
    m.extend(to_var_int(len(tx_out)))
    for value, script in tx_out:
        script = bytes.fromhex(script)
        m.extend(value.to_bytes(8, 'little'))
        m.extend(to_var_int(len(script)))
        m.extend(script)
    m.extend(lock_time.to_bytes(4, 'little'))
    return sha256(sha256(m).digest()).digest()

tx_hashes = []

version = 1
lock_time = 0

tx_in = [[['0000000000000000000000000000000000000000000000000000000000000000', 0xffffffff], '04f2b9441a022a01', 4294967295]]
tx_out = [[5001000000, '4104d879d5ef8b70cf0a33925101b64429ad7eb370da8ad0b05c9cd60922c363a1eada85bcc2843b7378e226735048786c790b30b28438d22acfade24ef047b5f865ac']]
tx_hashes.append(process_tx())

tx_in = [[['738d466ff93e7857d07138b5a5a75e83a964e3c9977d2603308ecc9b667962ad', 0], '4930460221009805aa00cb6f80ca984584d4ca40f637fc948e3dbe159ea5c4eb6941bf4eb763022100e1cc0852d3f6eb87839edca1f90169088ed3502d8cde2f495840acac69eefc9801410486477e6a23cb25c9a99f0c467c6fc86197e718ebfd41d1aef7cc3cbd75197c1f1aaba985b22b366a0729ccb8aa38277809d6d218cf4077ac9f29a953b5435222', 4294967295]]
tx_out = [[50000000, '76a9146f31097e564b9d54ebad662d5c4b5621c18ff52388ac'], [2900000000, '76a9147228033b48b380900501c39c61da4ab453ca88e888ac']]
tx_hashes.append(process_tx())

tx_in = [[['c9b85295d9301d18e319bfe395ccaed6953c85c437dfc7cef97120c441f3195a', 0], '473044022025bca5dc0fe42aca5f07c9b3fe1b3f72113ffbc3522f8d3ebb2457f5bdf8f9b2022030ff687c00a63e810b21e447d3a57b2749ebea553cab763eb9b99e1b9839653b014104469f7eb54b90d90106b1a5412b41a23516028e81ad35e0418a4460707ae39a4bf0101b632260fb08979aba0ceea576b5400c7cf30b539b055ec4c0b96ab00984', 4294967295], [['dac1581d713ef11db9710f202f2103cc918af29499ddbd11352bb7b6f4d3725b', 0], '493046022100fbef2589b7c52a3be0fd8dd3624445da9c8930f0e51f6a33d76dc0ca0304473d0221009ec433ca6a9f16184db46468ff39cafaa9643021e0c66a1de1e6f9a612092790014104b27f4de096ac6431eec4b807a0d3db3e9f9be48faab692d5559624acb1faf4334dd440ebf32a81506b7c49d8cf40e4b3f5c6b6e99fcb6d3e8a298174bd2b348d', 4294967295], [['430fbe9aea0fc6ceb6065bf3a0e911a8c6b1ca438e16a3338471518873942e29', 1], '4730440220582813f2c2d7cbb84521f81d6c2a1147e5296e90bee05f583b3df108fdac72010220232b43a2e596cef59f82c8bfff1a310d85e7beb3e607076ff8966d6d374dc12b014104a8514ca51137c6d8a4befa476a7521197b886fceafa9f5c2830bea6df62792a6dd46f2b26812b250f13fad473e5cab6dcceaa2d53cf2c82e8e03d95a0e70836b', 4294967295]]
tx_out = [[1000000, '76a914429e6bd3c9a9ca4be00a4b2b02fd4f5895c1405988ac'], [485000000, '76a914e55756cb5395a4b39369d0f1f0a640c12fd867b288ac']]
tx_hashes.append(process_tx())

tx_in = [[['7ae1847583b78ea9534b2da74134aa89a4d013a6b31631e71a27b9026435a8c8', 1], '4730440220771ae3ed7f2507f5682d6f63f59fa17187f1c4bdb33aa96373e73d42795d23b702206545376155d36db49560cf9c959d009f8e8ea668d93f47a4c8e9b27dc6b330230141048a976a8aa3f805749bf62df59168e49c163abafde1d2b596d685985807a221cbddf5fb72687678c41e35de46db82b49a48a2b9accea3648407c9ce2430724829', 4294967295], [['fec71848ed96aeef4bc10303b182aab03e565648ed3f6e0b36f748921c11f0a4', 1], '49304602210087fc57bd3ce0a03f0f7a3300a84dde8d5eba23dfdc64b8f2c17950c5213158d102210098141fbd22da33629cfc25b84d49b397144e1ec6287e0edd53dbb426aa6a72ed014104dee3ef362ae99b46422c8028f900a138c872776b2fcffed3f9cd02ee4b068a6df516a50249ae6d8f420f9ce19cdfc4663961296a71cd62b04a2c8a14ff89b1d0', 4294967295]]
tx_out = [[15000000, '76a914e43f7c61b3ef143b0fe4461c7d26f67377fd207588ac']]
tx_hashes.append(process_tx())

merkle_tree = tx_hashes[:]

while len(merkle_tree) > 1:
    if len(merkle_tree) % 2 == 1:
        merkle_tree.append(merkle_tree[-1])
    merkle_tree = [sha256(sha256(merkle_tree[2*i]+merkle_tree[2*i+1]).digest()).digest() for i in range(len(merkle_tree)//2)]
merkle_root = merkle_tree[0]

version = 1
prevBlockHash = '00000000000008a3a41b85b8b29ad444def299fee21793cd8b9e567eab02cd81'
time = 1305998791
bits = 440711666
nonce = 2504433986

m = bytearray()
m.extend(version.to_bytes(4, 'little'))
m.extend(bytes.fromhex(prevBlockHash)[::-1])
m.extend(merkle_root)
m.extend(time.to_bytes(4, 'little'))
m.extend(bits.to_bytes(4, 'little'))
m.extend(nonce.to_bytes(4, 'little'))
blockHash = sha256(sha256(m).digest()).digest()

print('TX Hashes:')
print('\n'.join(h[::-1].hex() for h in tx_hashes))

print('Merkle Root Hash:')
print(merkle_root[::-1].hex())

print('Block Hash:')
print(blockHash[::-1].hex())
