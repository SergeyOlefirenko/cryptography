import hashlib
import time
import json
import matplotlib.pyplot as plt
from pathlib import Path


# Hashing
def hash_block(data, prev_hash, nonce):
    
    # Generates a SHA-256 hash based on the data, previous hash, and nonce
    
    text = f"{data}{prev_hash}{nonce}".encode()
    return hashlib.sha256(text).hexdigest()


# Mining
def mine_block(block, difficulty=5):
    
    # Proof-of-Work: finds a nonce so that the hash starts with `difficulty` zeros
    
    prefix = "0" * difficulty
    nonce = 0
    start_time = time.time()

    while True:
        hash_val = hash_block(block['data'], block['prev_hash'], nonce)
        if hash_val.startswith(prefix):
            block['nonce'] = nonce
            block['hash'] = hash_val
            break
        nonce += 1

    elapsed = time.time() - start_time
    print(f"Data block {block['data']} mined"
          f"Nonce={nonce}, time={elapsed:.2f}с, hash={hash_val[:25]}...")
    #print(f"Data block {block['data']} mined "
          #f"Nonce={nonce}, time={elapsed:.2f}с, hash={hash_val}")

    return block, elapsed


# Adding a new block to the blockchain
def add_block(blockchain, data, difficulty=5):
    
    # Creates a new block, mines it, and adds it to the blockchain
    
    prev_hash = blockchain[-1]['hash'] if blockchain else ""
    new_block = {
        'data': data,
        'prev_hash': prev_hash,
        'nonce': None,
        'hash': None
    }

    mined_block, elapsed = mine_block(new_block, difficulty)
    blockchain.append(mined_block)
    return mined_block, elapsed


# Verifying the Blockchain Integrity
def validate_blockchain(blockchain):
    
    # Integrity of the entire blockchain verification
    
    for i in range(1, len(blockchain)):
        curr = blockchain[i]
        prev = blockchain[i - 1]

        # Chain link verification
        if curr['prev_hash'] != prev['hash']:
            print(f"Incorrect previous hash detected for the block {i}")
            return False

        # Hash verification
        recalculated_hash = hash_block(curr['data'], curr['prev_hash'], curr['nonce'])
        if recalculated_hash != curr['hash']:
            print(f"Invalid hash detected in the block {i}")
            return False

    print("Blockchain integrity verified. All blocks are sequential and valid")
    return True


# Difficulty adjustment
def create_blockchain(values, start_difficulty=5, target_time=1.0, adjust_interval=3):
    
    # Creates a blockchain with the given values. Automatically adjusts the difficulty based on the mining speed
    
    blockchain = []
    difficulty = start_difficulty
    times = []
    difficulties = []

    print("Creation of genesis block")
    genesis_block = {
        'data': "Genesis Block",
        'prev_hash': "",
        'nonce': None,
        'hash': None
    }
    genesis_block, elapsed = mine_block(genesis_block, difficulty)
    blockchain.append(genesis_block)
    times.append(elapsed)
    difficulties.append(difficulty)

    # Adding data blocks
    for i, val in enumerate(values, start=1):
        mined_block, elapsed = add_block(blockchain, val, difficulty)
        times.append(elapsed)
        difficulty = int(round(difficulty))
        #difficulties.append(difficulty)
        difficulties.append(int(difficulty))

        # Dynamic difficulty adjustment
        if i % adjust_interval == 0:
            avg_time = sum(times[-adjust_interval:]) / adjust_interval
            if avg_time < target_time / 2:
                difficulty += 1
                print(f"Average time {avg_time:.2f}с - difficulty increased to {difficulty}")
            elif avg_time > target_time * 2 and difficulty > 1:
                difficulty -= 1
                print(f"Average time {avg_time:.2f}с - difficulty reduced to {difficulty}")
    
    return blockchain, times, difficulties

# Loading or saving the blockchain
def save_blockchain(blockchain, filename="blockchain.json"):
   
    # Saves the blockchain to a JSON file
   
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(blockchain, f, indent=4, ensure_ascii=False)
    print(f"Blockchain saved to file: {filename}")


def load_blockchain(filename="blockchain.json"):

   # Loading the blockchain from a JSON file (if it exists)

    path = Path(filename)
    if not path.exists():
        print("blockchain.json file not found, creating a new blockchain")
        return None

    with open(filename, "r", encoding="utf-8") as f:
        blockchain = json.load(f)
    print(f"Blockchain loaded from lile: {filename}")
    return blockchain


# Displaying the change chart (for visualization purposes only)
def plot_stats(times, difficulties):

   # Displays mining time and difficulty charts

    blocks = list(range(len(times)))

    plt.figure(figsize=(10, 5))
    plt.gcf().canvas.manager.set_window_title("Mining statistics")

    # Time Chart
    plt.subplot(2, 1, 1)
    plt.plot(blocks, times, marker='o')
    plt.title("Mining time of each block")
    plt.xlabel("Block number")
    plt.ylabel("Seconds")

    # Difficulty Chart
    plt.subplot(2, 1, 2)
    plt.plot(blocks, difficulties, marker='s', color='orange')
    plt.title("Dynamics of difficulty change (difficulty)")
    plt.xlabel("Block number")
    plt.ylabel("Difficulty level")

    plt.tight_layout()
    plt.show()


# Running the Script
if __name__ == "__main__":
    values = [91911, 90954, 95590, 97390, 96578, 97211, 95090]
    start_difficulty = 5  # Initial Difficulty
    target_time = 1.0     # Block Processing Time (seconds)
    adjust_interval = 3   # Frequency of Difficulty Check and Adjustment

    # Checking if the blockchain file exists
    existing_chain = load_blockchain()

    if existing_chain:
        print("\nVerifying the Integrity of the downloaded blockchain")
        validate_blockchain(existing_chain)
    else:
        blockchain, times, difficulties = create_blockchain(values, start_difficulty, target_time, adjust_interval)

        print("\nFull Blockchain")
        for i, block in enumerate(blockchain):
            print(f"\nBlock {i}:")
            for key, val in block.items():
                print(f"  {key}: {val}")

        print("\nIntegrity Check")
        validate_blockchain(blockchain)

        save_blockchain(blockchain)

        print("\nVisualization of Statistical Data")
        plot_stats(times, difficulties)
