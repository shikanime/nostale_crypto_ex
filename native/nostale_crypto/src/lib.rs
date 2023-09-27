use rustler::{Binary, Env, NewBinary, NifTuple, OwnedBinary};

const SEPARATOR: u8 = 0xd8;

macro_rules! str {
    ($value:expr) => {
        String::from_utf8($value).expect("invalid UTF-8 string")
    };
}

#[derive(NifTuple)]
struct LoginNextResult<'a> {
    packet: Option<Binary<'a>>,
    remaining: Binary<'a>,
}

#[rustler::nif]
fn login_next<'a>(env: Env<'a>, raw: Binary<'a>) -> LoginNextResult<'a> {
    match do_login_next(raw.as_slice()) {
        Some((packet, remaining)) => {
            let mut pb = NewBinary::new(env, packet.len());
            pb.as_mut_slice().copy_from_slice(packet);
            let mut rb = NewBinary::new(env, remaining.len());
            rb.as_mut_slice().copy_from_slice(remaining);
            LoginNextResult {
                packet: Some(pb.into()),
                remaining: rb.into(),
            }
        }
        None => LoginNextResult {
            packet: None,
            remaining: raw,
        },
    }
}

fn do_login_next(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    let index = raw.iter().position(|&r| r == SEPARATOR);

    match index {
        Some(i) => Some((&raw[0..i], &raw[i + 1..])),
        _ => None,
    }
}

#[rustler::nif]
fn login_encrypt(raw: String) -> OwnedBinary {
    let enc: Vec<u8> = do_login_encrypt(raw.as_bytes());
    let mut binary: OwnedBinary = OwnedBinary::new(enc.len()).unwrap();
    binary.as_mut_slice().copy_from_slice(&enc);

    binary
}

fn do_login_encrypt(raw: &[u8]) -> Vec<u8> {
    raw.into_iter().map(|x| x.wrapping_add(0xf)).collect()
}

#[rustler::nif]
fn login_decrypt(raw: Binary) -> String {
    let dec: Vec<u8> = do_login_decrypt(raw.as_slice());

    str!(dec)
}

fn do_login_decrypt(raw: &[u8]) -> Vec<u8> {
    raw.into_iter()
        .map(|x| x.wrapping_sub(0xf) ^ 0xc3)
        .collect()
}

rustler::init!(
    "Elixir.NostaleCrypto.Native",
    [login_next, login_encrypt, login_decrypt]
);
