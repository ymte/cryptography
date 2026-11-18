use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;
use sha2::{Digest, Sha512};
use std::env;
use std::error::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use std::io::BufRead;
use tokio::sync::mpsc;

// Include your FFDHE8192 prime here.
include!("ffdhe.rs");

const BLOCK_SIZE: usize = 64;

// --------------------------------------------------
// SHA-512 of a 512-bit little-endian integer
// --------------------------------------------------

fn sha512_bigint(int: &BigUint) -> [u8; 64] {
    let mut bytes = [0u8; 64];

    let mut n = int.clone();

    for byte in bytes.iter_mut() {
        *byte = (&n % 256u32).try_into().unwrap();
        n /= 256u32;
    }

    let hash = Sha512::digest(bytes);

    hash.into()
}

// --------------------------------------------------
// Padding
// --------------------------------------------------

fn pad(plaintext: &[u8]) -> Vec<u8> {
    let padding = BLOCK_SIZE - (plaintext.len() % BLOCK_SIZE);

    let mut padded = plaintext.to_vec();
    padded.extend(std::iter::repeat(padding as u8).take(padding));

    padded
}

fn unpad(padded: &[u8]) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    if padded.is_empty() {
        return Err("Invalid padding".into());
    }

    let padding = *padded.last().unwrap() as usize;

    if padding == 0 || padding > BLOCK_SIZE || padding > padded.len() {
        return Err("Invalid padding".into());
    }

    if !padded[padded.len() - padding..]
        .iter()
        .all(|&b| b == padding as u8)
    {
        return Err("Invalid padding".into());
    }

    Ok(padded[..padded.len() - padding].to_vec())
}

// --------------------------------------------------
// Encryption
// --------------------------------------------------

fn encrypt(
    plaintext: &str,
    key: &BigUint,
) -> Vec<u8> {
    let plaintext = pad(plaintext.as_bytes());

    let mut ciphertext = Vec::new();

    for (index, block) in plaintext.chunks(BLOCK_SIZE).enumerate() {
        // Julia indices start at 1.
        let block_index = BigUint::from(index * BLOCK_SIZE + 1);

        let hash = sha512_bigint(&(key + block_index));

        let encrypted: Vec<u8> = block
            .iter()
            .zip(hash.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        ciphertext.extend(encrypted);
    }

    ciphertext
}

fn decrypt(
    ciphertext: &[u8],
    key: &BigUint,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    if ciphertext.is_empty() || ciphertext.len() % BLOCK_SIZE != 0 {
        return Err("Invalid ciphertext length".into());
    }

    let mut plaintext = Vec::new();

    for (index, block) in ciphertext.chunks(BLOCK_SIZE).enumerate() {
        let block_index = BigUint::from(index * BLOCK_SIZE + 1);

        let hash = sha512_bigint(&(key + block_index));

        let decrypted: Vec<u8> = block
            .iter()
            .zip(hash.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        plaintext.extend(decrypted);
    }

    let plaintext = unpad(&plaintext)?;

    Ok(String::from_utf8(plaintext)?)
}

// --------------------------------------------------
// Encoding / decoding
// --------------------------------------------------

fn encode(plaintext: &str, key: &BigUint) -> String {
    let hash = crc32c::crc32c(plaintext.as_bytes());

    let message = format!("{} {}", hash, plaintext);

    hex::encode(encrypt(&message, key))
}

fn decode(
    hex_data: &str,
    key: &BigUint,
) -> Result<String, Box<dyn Error + Send + Sync>> {
    let data = hex::decode(hex_data)?;

    let message = decrypt(&data, key)?;

    let (hash, plaintext) = message
        .split_once(' ')
        .ok_or("Invalid message format")?;

    let expected_hash: u32 = hash.parse()?;

    let actual_hash = crc32c::crc32c(plaintext.as_bytes());

    if expected_hash != actual_hash {
        return Err("CRC32c mismatch".into());
    }

    Ok(plaintext.to_string())
}

// --------------------------------------------------
// Diffie-Hellman key exchange
// --------------------------------------------------

async fn kex(
    stream: &mut TcpStream,
) -> Result<BigUint, Box<dyn Error + Send + Sync>> {
    let mut rng = thread_rng();

    // Julia: rand(device, big(1):big(2)^512)
    let a = rng.gen_biguint_range(
        &BigUint::one(),
        &(BigUint::one() << 512usize),
    );

    let g = BigUint::from(2u32);

    // ffdhe8192 is supplied by ffdhe.rs.
    let p = BigUint::parse_bytes(FFDHE8192.as_bytes(), 10)
        .ok_or("Invalid FFDHE prime")?;

    // A = g^a mod p
    let a_public = g.modpow(&a, &p);

    stream
        .write_all(format!("{}\n", a_public).as_bytes())
        .await?;

    stream.flush().await?;

    // Receive B.
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    reader.read_line(&mut line).await?;

    let b_public = BigUint::parse_bytes(line.trim().as_bytes(), 10)
        .ok_or("Invalid public key")?;

    // Shared secret.
    let secret = b_public.modpow(&a, &p);

    Ok(secret)
}

// --------------------------------------------------
// Chat
// --------------------------------------------------

async fn run_client_server(
    mut stream: TcpStream,
    is_client: bool,
) -> Result<(), Box<dyn Error + Send + Sync>> {

    let secret = kex(&mut stream).await?;

    println!("secret {}", &secret % 1_000_000_000u64);

    // key = secret % 2^512
    let key = &secret % (BigUint::one() << 512usize);

    let client_offset = if is_client {
        BigUint::zero()
    } else {
        BigUint::from(1_000_000_000u64)
    };

    let server_offset = if !is_client {
        BigUint::zero()
    } else {
        BigUint::from(1_000_000_000u64)
    };

    let (read_half, mut write_half) = stream.into_split();

    // Receive task.
    let receive_key = key.clone();
    let receive_offset = client_offset.clone();

    let mut receive_task = tokio::spawn(async move {
        let mut reader = BufReader::new(read_half);
        let mut index = BigUint::one();

        loop {
            let mut hex_line = String::new();

            match reader.read_line(&mut hex_line).await {
                Ok(0) => {
                    println!("disconnected");
                    break;
                }
                Ok(_) => {}
                Err(_) => {
                    println!("protocol error");
                    break;
                }
            }

            let hex_line = hex_line.trim();

            if hex_line.is_empty() {
                println!("disconnected");
                break;
            }

            let message_key = &receive_key + &receive_offset + &index;

            match decode(hex_line, &message_key) {
                Ok(plaintext) => println!("{}", plaintext),
                Err(_) => {
                    println!("protocol error");
                    break;
                }
            }

            index += BigUint::one();
        }
    });

    // Send task.
    let send_key = key.clone();
    let send_offset = server_offset;

	let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<String>();

	// Read terminal input on a detached thread.
	std::thread::spawn(move || {
		let stdin = std::io::stdin();

		for line in stdin.lock().lines() {
			match line {
				Ok(line) => {
					if stdin_tx.send(line).is_err() {
						break;
					}
				}
				Err(_) => break,
			}
		}
	});

	// Send task.
	let mut send_task = tokio::spawn(async move {
		let mut index = BigUint::one();

		while let Some(plaintext) = stdin_rx.recv().await {
			if plaintext.is_empty() {
				break;
			}

			let message_key = &send_key + &send_offset + &index;
			let hex = encode(&plaintext, &message_key);

			if write_half.write_all(format!("{}\n", hex).as_bytes()).await.is_err() {
				break;
			}

			if write_half.flush().await.is_err() {
				break;
			}

			index += BigUint::one();
		}
	});


	tokio::select! {
		_ = &mut receive_task => {
			send_task.abort();
		},
		_ = &mut send_task => {
			receive_task.abort();
		},
	}

	Ok(())
}

// --------------------------------------------------
// Main
// --------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let args: Vec<String> = env::args().collect();

    let (stream, is_client) = if args.len() == 1 {
        println!("listening...");

        let listener = TcpListener::bind("[::]:2000").await?;

        let (stream, _) = listener.accept().await?;

        println!("accepted");

        (stream, false)
    } else {
        println!("connecting...");

        let stream = TcpStream::connect(
            format!("{}:2000", args[1])
        ).await?;

        println!("connected");

        (stream, true)
    };

    run_client_server(stream, is_client).await?;

    Ok(())
}
