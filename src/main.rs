use blake3;
use blake3::Hash;
use std::collections::VecDeque;
use std::collections::BTreeMap;
use std::time::Instant;

const INCREMENTAL_HASHES: i16 = 100;

fn hash(nonce: &[u8]) -> Hash {
    let mut current_hash = blake3::hash(nonce);
    for _ in 0..INCREMENTAL_HASHES {
        let mut hasher = blake3::Hasher::new();
        hasher.update(current_hash.as_bytes());
        current_hash = hasher.finalize();
    }
    current_hash
}

fn generate_nonce(nonce_hash_map: &mut BTreeMap<[u8; 4], Hash>) -> Option<[u8; 4]> {
    let mut nonce = [0u8; 4];

    // Increment the nonce until we find one that isn't in the map
    while nonce_hash_map.contains_key(&nonce) {
        // Increment the nonce as a 4-byte little-endian integer
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
        if nonce == [0u8; 4] {
            return None;
        }
    }

    Some(nonce)
}

fn reduce_hash_to_nonce(hash: &blake3::Hash) -> [u8; 4] {
    let hash_bytes = hash.as_bytes(); // Get the 32-byte hash
    let mut nonce = [0u8; 4];

    // Truncate the first 4 bytes
    nonce.copy_from_slice(&hash_bytes[0..4]);

    // XOR folding: XOR the remaining bytes into the first 4 bytes
    for chunk in hash_bytes[4..].chunks_exact(4) {
        for i in 0..4 {
            nonce[i] ^= chunk[i];
        }
    }

    nonce
}

const SHOW_GENERATION_INFO: bool = true; // Set to `false` to disable generation info

fn generate_tree(nonce_hash_map: &mut BTreeMap<[u8; 4], Hash>) {
    let mut queue: VecDeque<[u8; 4]> = VecDeque::new();
    let mut count = 0;
    let mut collisions = 0;
    const TOTAL_NONCES: u64 = 256 * 256 * 256 * 256; // 4,294,967,296

    // Start timing
    let start_time = Instant::now();

    // Start with an initial nonce
    if let Some(nonce) = generate_nonce(nonce_hash_map) {
        queue.push_back(nonce);
    }

    while let Some(nonce) = queue.pop_front() {
        let hash_result = hash(&nonce);
        nonce_hash_map.insert(nonce, hash_result);

        let next_nonce = reduce_hash_to_nonce(&hash_result);
        if !nonce_hash_map.contains_key(&next_nonce) && !queue.contains(&next_nonce) {
            queue.push_back(next_nonce);
        } else {
            collisions += 1; // Increment collision count
        }

        // Print progress and timing information (conditionally)
        if SHOW_GENERATION_INFO {
            count += 1;
            if count % 1_000_000 == 0 {
                let elapsed_time = start_time.elapsed();
                let hashes_per_second = count as f64 / elapsed_time.as_secs_f64();
                let progress = (count as f64 / TOTAL_NONCES as f64) * 100.0;

                // Estimate remaining time
                let remaining_nonces = TOTAL_NONCES - count;
                let estimated_remaining_time = (remaining_nonces as f64) / hashes_per_second;
                let estimated_total_time = elapsed_time.as_secs_f64() + estimated_remaining_time;

                println!(
                    "Processed {} nonces ({:.2}%) | {:.2} hashes/sec | Elapsed: {:.2}s | Remaining: {:.2}s | Total: {:.2}s | Collisions: {}",
                    count,
                    progress,
                    hashes_per_second,
                    elapsed_time.as_secs_f64(),
                    estimated_remaining_time,
                    estimated_total_time,
                    collisions
                );
            }
        }

        // If the queue is empty, try generating a new nonce
        if queue.is_empty() {
            if let Some(new_nonce) = generate_nonce(nonce_hash_map) {
                queue.push_back(new_nonce);
            } else {
                println!("All possible nonces have been exhausted.");
                break;
            }
        }
    }

    if SHOW_GENERATION_INFO {
        let total_time = start_time.elapsed();
        println!("Total collisions: {}", collisions);
        println!("Total time taken: {:.2} seconds", total_time.as_secs_f64());
    }
}

fn main() {
    let mut nonce_hash_map: BTreeMap<[u8; 4], Hash> = BTreeMap::new();
    generate_tree(&mut nonce_hash_map);

    // Print all entries in the map (optional)
    println!("All entries in the map:");
    for (key, value) in &nonce_hash_map {
        println!("{:?}: {}", key, value);
    }
}

