use blake3;
use blake3::Hash;
use std::collections::VecDeque;
use std::collections::BTreeMap;
use std::time::Instant;

// Configuration constants
const NONCE_SIZE: usize = 4; // Change this to 3, 4, 5, etc.
const INCREMENTAL_REDUCTION: i16 = 100;
const TOT_NONCE_HASH_DIST: i16 = 1000;



const NONCE_HASH_DIST: i16 = TOT_NONCE_HASH_DIST / INCREMENTAL_REDUCTION;

fn hash(nonce: &[u8]) -> Hash {
    let mut current_hash = blake3::hash(nonce);
    for _ in 0..INCREMENTAL_REDUCTION {
        let mut hasher = blake3::Hasher::new();
        hasher.update(current_hash.as_bytes());
        current_hash = hasher.finalize();
    }
    current_hash
}

fn generate_nonce(nonce_hash_map: &mut BTreeMap<Vec<u8>, Hash>) -> Option<Vec<u8>> {
    let mut nonce = vec![0u8; NONCE_SIZE];

    // Increment the nonce until we find one that isn't in the map
    while nonce_hash_map.contains_key(&nonce) {
        // Increment the nonce as a little-endian integer
        let mut carry = 1;
        for byte in nonce.iter_mut().rev() {
            let (new_byte, new_carry) = byte.overflowing_add(carry);
            *byte = new_byte;
            carry = new_carry as u8;
            if carry == 0 {
                break;
            }
        }

        // If the nonce overflows, return None to indicate completion
        if nonce.iter().all(|&b| b == 0) {
            return None;
        }
    }

    Some(nonce)
}

fn reduce_hash_to_nonce(hash: &blake3::Hash) -> Vec<u8> {
    let hash_bytes = hash.as_bytes(); // Get the 32-byte hash
    let mut nonce = vec![0u8; NONCE_SIZE];

    // Truncate the first NONCE_SIZE bytes
    nonce.copy_from_slice(&hash_bytes[0..NONCE_SIZE]);

    // XOR folding: XOR the remaining bytes into the nonce
    for chunk in hash_bytes[NONCE_SIZE..].chunks_exact(NONCE_SIZE) {
        for i in 0..NONCE_SIZE {
            nonce[i] ^= chunk[i];
        }
    }

    nonce
}

fn generate_tree(nonce_hash_map: &mut BTreeMap<[u8; NONCE_SIZE], Hash>) {
    let mut queue: VecDeque<&[u8; 4]>= VecDeque::new();
    let mut result: Hash;

    let mut collisions = 0;

    while let Some(nonce) = generate_nonce(nonce_hash_map) {
        queue.push_back(&nonce);
        let mut collision_occur = false;
        for _ in 0..NONCE_HASH_DIST{
            result = hash(&nonce);
            nonce = reduce_hash_to_nonce(&result);
            if !collision_occur && !nonce_hash_map.contains_key(&nonce) && !queue.contains(&nonce) {
                queue.push_back(&nonce);
            }
            else {
                collisions += 1;
            }
        }

        while let Some(insert_nonce) = queue.pop_front() {
            nonce_hash_map.insert(insert_nonce, result);

            result = hash(&nonce);
            nonce = reduce_hash_to_nonce(&result);

            if !collision_occur && !nonce_hash_map.contains_key(&nonce) && !queue.contains(&nonce) {
                queue.push_back(&nonce);
            }
        }
    }
    println!("There were {} collisions", count);
}

fn main() {
    let mut nonce_hash_map: BTreeMap<Vec<u8>, Hash> = BTreeMap::new();
    generate_tree(&mut nonce_hash_map);

    // Print all entries in the map (optional)
    println!("All entries in the map:");
    for (key, value) in &nonce_hash_map {
        println!("{:?}: {}", key, value);
    }
}
