use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, AeadCore, KeyInit, OsRng},
    Aes128Gcm, Key, Nonce,
};
use circular_buffer::CircularBuffer;
use labrador_ldpc::LDPCCode;
use opencv::{
    core::{Mat, Vector},
    imgcodecs,
    prelude::*,
    videoio,
};
use std::io::Read;
use std::time::{Duration, Instant};
use std::vec;
use typenum;

const PRIVATE_KEY: &str = "0123456789abcdef"; // 128 bits = 16 bytes

// takes 100 bytes of data as input and returns 128 bytes = 1024 bits of cipher text, this 128 bytes includes 12 bytes + 16 bytes + 100 bytes

fn encrypt(private_key: &str, plain_text: Vec<u8>) -> Vec<u8> {
    let key = Key::<Aes128Gcm>::from_slice(private_key.as_bytes());
    let nonce = Aes128Gcm::generate_nonce(&mut OsRng);

    let cipher = Aes128Gcm::new(key);

    let cipher_text: Vec<u8> = cipher
        .encrypt(&nonce, plain_text.as_ref())
        .expect("failed to encrypt");

    let mut encrypted_data: Vec<u8> = nonce.to_vec();
    encrypted_data.extend_from_slice(&cipher_text);

    return encrypted_data;
}

// takes 128 bytes of data as input which includes 12 bytes + 16 bytes + 100 bytes and returns 100 bytes = 800 bits of plain text

fn decrypt(private_key: &str, cipher_text: Vec<u8>) -> Vec<u8> {
    let key = Key::<Aes128Gcm>::from_slice(private_key.as_bytes());

    let (nonce_arr, cipher_data) = cipher_text.split_at(12);

    let nonce: &GenericArray<u8, typenum::U12> = Nonce::from_slice(nonce_arr);

    let cipher = Aes128Gcm::new(key);

    let plaintext: Vec<u8> = cipher
        .decrypt(nonce, cipher_data)
        .expect("failed to decrypt");

    // return String::from_utf8(plaintext).expect("failed to convert to string");
    return plaintext;
}

fn main() {
    let ldpc: LDPCCode = LDPCCode::TM2048; // k = 1024, n = 2048, r = 1/2

    let mut cam: videoio::VideoCapture = videoio::VideoCapture::new(0, videoio::CAP_ANY)
        .expect("Error creating video capture instance");

    let mut frame = Mat::default();
    let mut buf = Vector::new();

    let mut cir_buf: CircularBuffer<1000000, u8> = CircularBuffer::<1_000_000, u8>::new(); // 976 KB = 9 frames approx 1 frame = 100 KB

    // 1st thread

    let mut i = 0;

    loop {
        if i == 1 {
            break;
        }

        cam.read(&mut frame).expect("Error reading frame");

        imgcodecs::imencode(".jpg", &frame, &mut buf, &Vector::new())
            .expect("Error encoding frame");

        cir_buf.extend(buf.iter());
        cir_buf.push_back(b'\n');

        println!("Circular buffer Frame size: {:?}", cir_buf.len());
        println!("Circular buffer: {:?}", cir_buf);
        println!();

        imgcodecs::imwrite("output.jpg", &frame, &Vector::new()).expect("Error while creating image");

        i = i + 1;
    }

    // 2nd thread

    let mut buf2: Vec<u8> = vec![0u8; 100];

    loop {
        if cir_buf.is_empty() {
            break;
        } else {
            cir_buf.read_exact(&mut buf2).expect("Error reading from circular buffer");

            println!("Actual data of 100 bytes: {:?}", buf2);

            // let plain_text: &str = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890"; // 100 bytes

            let data: Vec<u8> = encrypt(PRIVATE_KEY, buf2.clone()); // k = 1024 bits = 128 bytes // 100 bytes of plain text data produces 128 bytes of cipher text

            let mut codeword: Vec<u8> = vec![0u8; ldpc.n() / 8]; // n = 2048 bits = 256 bytes

            println!();

            println!("128 bytes of Cipher Text of actual 100 bytes data : {:?}", data);
            println!();

            let mut start: Instant = Instant::now();
            ldpc.copy_encode(&data, &mut codeword); 
            let mut duration: Duration = start.elapsed();

            println!("Encoding Time : {:?}", duration);
            println!();

            // for j in data.iter() {
            //     print!("{:08b} ", j);
            // }

            // println!();
            // println!();

            for i in codeword.iter() { // codeword is now of n = 2048 bits = 256 bytes
                print!("{:08b} ", i);
            }

            println!();
            println!();

            println!("In Device 2");
            println!();

            let mut rx_codeword: Vec<u8> = codeword.clone();
            rx_codeword[0] = 0b00000000;

            for j in rx_codeword.iter() {
                print!("{:08b} ", j);
            }

            println!();
            println!();

            let mut working_space: Vec<u8> = vec![0u8; ldpc.decode_bf_working_len()];
            let mut rx_data: Vec<u8> = vec![0u8; ldpc.output_len()];

            start = Instant::now();
            ldpc.decode_bf(&rx_codeword, &mut rx_data, &mut working_space, 20);
            duration = start.elapsed();

            println!("Decoding Time : {:?}", duration);
            println!();

            let actual_data: Vec<u8> = rx_data[..128].to_vec();

            println!("Decoded data which is cipher text of 128 bytes : {:?}", actual_data);
            println!();

            // for i in actual_data.iter() {
            //     print!("{:08b} ", i);
            // }

            // println!();

            assert_eq!(&data, &actual_data);

            let message: Vec<u8> = decrypt(PRIVATE_KEY, actual_data);

            println!("Decrypted message of 100 bytes : {:?}", message);

            assert_eq!(&message, &buf2);

            println!();
            println!("Repeat with next 100 bytes of data"); 
            println!();
        }
    }
}
