import asyncio
import json
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from utils import *

STATE_PATH = STATE_ALICE
MY_PRIV, MY_PUB = ALICE_PRIV, ALICE_PUB
THEIR_PUB = BOB_PUB

async def receive_loop(reader, dr: DoubleRatchet, their_pub_sign):
    while True:
        raw = await reader.readline()
        if not raw:
            break
        try:
            payload = unpack_payload(raw)
            sig = ub64(payload['signature'])
            header_bytes = json.dumps(payload['header'], separators=(',', ':'), sort_keys=True).encode()
            if not verify(their_pub_sign, sig, header_bytes + ub64(payload['nonce']) + ub64(payload['ciphertext'])):
                show('Invalid signature — dropped')
                prompt()
                continue
            pt = dr.decrypt_message(payload)
            show(pt)
        except Exception as e:
            show(f'Error: {e}')
        prompt()

async def send_loop(writer, dr: DoubleRatchet, priv_sign):
    while True:
        msg = await read_message_from_stdin()
        if not msg:
            continue
        plaintext = msg.strip().encode()
        payload = dr.encrypt_message(plaintext)
        header_bytes = json.dumps(payload['header'], separators=(',', ':'), sort_keys=True).encode()
        signature = sign(priv_sign, header_bytes + ub64(payload['nonce']) + ub64(payload['ciphertext']))
        packet = pack_payload(payload['header'], ub64(payload['nonce']), ub64(payload['ciphertext']), signature)
        writer.write(packet)
        await writer.drain()
        prompt()

async def handle_connection(reader, writer):
    ensure_ed25519_keys(MY_PRIV, MY_PUB)
    priv_sign = load_ed25519_private(MY_PRIV)
    their_pub_sign = load_ed25519_public(THEIR_PUB)

    print('Alice fingerprint:', fingerprint_pubkey(Path(MY_PUB).read_bytes()))
    print('Bob fingerprint:  ', fingerprint_pubkey(Path(THEIR_PUB).read_bytes()))
    if input('Confirm fingerprint is correct? (y/N): ').strip().lower() != 'y':
        print('Abort')
        writer.close()
        await writer.wait_closed()
        return

    dr = DoubleRatchet()

    # Generate ephemeral DH for Alice
    our_x = x25519.X25519PrivateKey.generate()
    our_x_pub = our_x.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    sig = sign(priv_sign, our_x_pub)
    writer.write((json.dumps({'dh_pub': b64(our_x_pub), 'signature': b64(sig)}, separators=(',', ':'), sort_keys=True) + '\n').encode())
    await writer.drain()

    # Receive Bob ephemeral
    raw = await reader.readline()
    obj = json.loads(raw.decode())
    their_dh = ub64(obj['dh_pub'])
    their_sig = ub64(obj['signature'])
    if not verify(their_pub_sign, their_sig, their_dh):
        print('Ephemeral signature verification failed')
        writer.close()
        await writer.wait_closed()
        return

    # Initialize Double Ratchet
    dr.DHs = our_x
    dr.DHr = their_dh
    dh_shared = dr.DHs.exchange(dr.x25519_pub_from_bytes(dr.DHr))
    dr.root_key = hkdf(32, dh_shared, None, b"root_init")

    rk_send, ck_send = dr.kdf_root(dr.root_key, dh_shared, b"_alice_send")
    rk_recv, ck_recv = dr.kdf_root(dr.root_key, dh_shared, b"_bob_send")
    dr.root_key = rk_send
    dr.send_chain_key = ck_send
    dr.recv_chain_key = ck_recv

    dr.Ns = dr.Nr = dr.PN = 0
    dr.save_state(STATE_PATH)

    print("Connected!"); prompt()
    await asyncio.gather(receive_loop(reader, dr, their_pub_sign), send_loop(writer, dr, priv_sign))

if __name__ == '__main__':
    print('Starting Alice... Waiting for Bob...')
    async def main():
        server = await asyncio.start_server(handle_connection, SERVER_HOST, SERVER_PORT)
        async with server:
            await server.serve_forever()
    asyncio.run(main())
