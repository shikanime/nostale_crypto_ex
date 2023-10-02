use rustler::{Binary, Env, NewBinary};

const LOGIN_SEPARATOR: u8 = 0xd8;

#[rustler::nif]
fn login_next<'a>(env: Env<'a>, raw: Binary<'a>) -> (Option<Binary<'a>>, Binary<'a>) {
    match next(raw.as_slice(), LOGIN_SEPARATOR) {
        Some((packet, remaining)) => {
            let mut pb = NewBinary::new(env, packet.len());
            pb.as_mut_slice().copy_from_slice(packet);
            let mut rb = NewBinary::new(env, remaining.len());
            rb.as_mut_slice().copy_from_slice(remaining);
            (Some(pb.into()), rb.into())
        }
        None => (None, raw),
    }
}

#[rustler::nif]
fn login_encrypt<'a>(env: Env<'a>, raw: String) -> Binary<'a> {
    let enc: Vec<u8> = do_login_encrypt(raw.as_bytes());
    let mut binary = NewBinary::new(env, enc.len());
    binary.as_mut_slice().copy_from_slice(&enc);

    binary.into()
}

fn do_login_encrypt(raw: &[u8]) -> Vec<u8> {
    raw.into_iter().map(|x| x.wrapping_add(0xf)).collect()
}

#[rustler::nif]
fn login_decrypt(raw: Binary) -> String {
    let dec: Vec<u8> = do_login_decrypt(raw.as_slice());

    String::from_utf8(dec).unwrap()
}

fn do_login_decrypt(raw: &[u8]) -> Vec<u8> {
    raw.into_iter()
        .map(|x| x.wrapping_sub(0xf) ^ 0xc3)
        .collect()
}

#[rustler::nif]
fn world_next<'a>(env: Env<'a>, raw: Binary<'a>, key: u16) -> (Option<Binary<'a>>, Binary<'a>) {
    let delimiter = pack_delimiter(cipher_mode(key), cipher_offset(key));
    match next(raw.as_slice(), delimiter) {
        Some((packet, remaining)) => {
            let mut pb = NewBinary::new(env, packet.len());
            pb.as_mut_slice().copy_from_slice(packet);
            let mut rb = NewBinary::new(env, remaining.len());
            rb.as_mut_slice().copy_from_slice(remaining);
            (Some(pb.into()), rb.into())
        }
        None => (None, raw),
    }
}

#[rustler::nif]
fn world_encrypt<'a>(env: Env<'a>, raw: String) -> Binary<'a> {
    let enc = encrypt_world_packet(raw.as_bytes());
    let mut binary = NewBinary::new(env, enc.len());
    binary.as_mut_slice().copy_from_slice(&enc);
    binary.into()
}

pub fn encrypt_world_packet(packet: &[u8]) -> Vec<u8> {
    let bytes = packet.iter().enumerate();
    let len = bytes.len();
    let mut encrypted_packet = Vec::with_capacity(len + 1);
    for (i, c) in bytes {
        if i % 0x7E != 0 {
            encrypted_packet.push(!c);
        } else {
            let remaining = if len - i > 0x7E { 0x7E } else { len - i };
            encrypted_packet.push(remaining.try_into().unwrap());
            encrypted_packet.push(!c);
        }
    }
    encrypted_packet.push(0xFF);
    encrypted_packet
}

#[rustler::nif]
pub fn world_session_decrypt<'a>(env: Env<'a>, packet: Binary<'a>) -> Binary<'a> {
    let enc = decrypt_session_packet(packet.as_slice());
    let mut binary = NewBinary::new(env, enc.len());
    binary.as_mut_slice().copy_from_slice(&enc);
    binary.into()
}

fn decrypt_session_packet(packet: &[u8]) -> Vec<u8> {
    let mut decrypted_packet = Vec::with_capacity(packet.len() * 2);
    for b in packet {
        let first_byte = b.wrapping_sub(0xF);
        let second_byte = first_byte & 0xF0;
        let first_key = first_byte - second_byte;
        let second_key = second_byte >> 0x4;
        decrypted_packet.push(decrypt_session_byte(second_key));
        decrypted_packet.push(decrypt_session_byte(first_key));
    }
    decrypted_packet
}

#[rustler::nif]
pub fn world_channel_decrypt<'a>(env: Env<'a>, packet: Binary<'a>, key: u16) -> Binary<'a> {
    let enc = decrypt_channel_packet(packet.as_slice(), cipher_mode(key), cipher_offset(key));
    let mut binary = NewBinary::new(env, enc.len());
    binary.as_mut_slice().copy_from_slice(&enc);
    binary.into()
}

fn decrypt_channel_packet(packet: &[u8], mode: u8, offset: u8) -> Vec<u8> {
    let mut decrypted_packet = Vec::with_capacity(packet.len());
    for b in packet {
        decrypted_packet.push(match mode {
            0 => b.wrapping_sub(offset),
            1 => b.wrapping_add(offset),
            2 => b.wrapping_sub(offset ^ 0xC3),
            3 => b.wrapping_add(offset ^ 0xC3),
            _ => b.wrapping_sub(0x0F),
        })
    }
    decrypted_packet
}

fn decrypt_session_byte(key: u8) -> u8 {
    match key {
        0 => 0x20,
        1 => 0x20,
        2 => 0x2D,
        3 => 0x2E,
        _ => 0x2C + key,
    }
}

/// Decrypt the delimiter from a key.
fn pack_delimiter(offset: u8, mode: u8) -> u8 {
    match mode {
        0 => 0xFF_u8.wrapping_add(offset),
        1 => 0xFF_u8.wrapping_sub(offset),
        2 => 0xFF_u8.wrapping_add(offset ^ 0xC3),
        3 => 0xFF_u8.wrapping_sub(offset ^ 0xC3),
        _ => 0x0F,
    }
}

/// Decrypt the offset from a key.
fn cipher_offset(key: u16) -> u8 {
    key as u8
}

/// Decrypt the mode from a key.
fn cipher_mode(key: u16) -> u8 {
    ((key >> 6) & 3) as u8
}

/// Get the next packet from a raw binary.
fn next<'a>(raw: &[u8], delimiter: u8) -> Option<(&[u8], &[u8])> {
    let index = raw.iter().position(|&r| r == delimiter);
    match index {
        Some(i) => Some((&raw[0..i], &raw[i + 1..])),
        _ => None,
    }
}

rustler::init!(
    "Elixir.NostaleCrypto.Native",
    [
        login_next,
        login_encrypt,
        login_decrypt,
        world_next,
        world_encrypt,
        world_session_decrypt,
        world_channel_decrypt
    ]
);
