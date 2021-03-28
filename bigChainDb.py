from bigchaindb_driver import BigchainDB
from bigchaindb_driver.crypto import generate_keypair

bdb_root_url = 'https://localhost:3001'
bdb = BigchainDB(bdb_root_url)
alice, bob = generate_keypair(), generate_keypair()
bicycle = {'data': {'bicycle': {'serial_number': 'abcd1234','manufacturer': 'bkfab',},},}
metadata = {'planet': 'earth'}
prepared_creation_tx = bdb.transactions.prepare(operation='CREATE',signers=alice.public_key,asset=bicycle,metadata=metadata,)
print(alice.private_key,alice.public_key)
print("prepared_creation_tx: ",prepared_creation_tx)
print("\n")
fulfilled_creation_tx = bdb.transactions.fulfill(prepared_creation_tx, private_keys=alice.private_key)
print("fulfilled_creation_tx :",fulfilled_creation_tx)
sent_creation_tx = bdb.transactions.send_commit(fulfilled_creation_tx)
if(sent_creation_tx == fulfilled_creation_tx):
    print("True")
