//! A minimal CBOR reader for App Attest objects: definite-length unsigned
//! and negative integers, byte and text strings, arrays, maps and simple
//! values. Anything else (indefinite lengths, tags, floats) is refused.

use crate::AttestError;

#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
    Uint(u64),
    Nint(u64),
    Bytes(&'a [u8]),
    Text(&'a str),
    Array(Vec<Value<'a>>),
    Map(Vec<(Value<'a>, Value<'a>)>),
    Simple(u8),
}

impl<'a> Value<'a> {
    /// The value under text key `key` in a map.
    pub fn get(&self, key: &str) -> Option<&Value<'a>> {
        match self {
            Value::Map(m) => m.iter().find(|(k, _)| *k == Value::Text(key)).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn bytes(&self) -> Option<&'a [u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }
}

const MAX_DEPTH: usize = 8;
const MAX_ITEMS: u64 = 64;

fn bad() -> AttestError {
    AttestError::Malformed("CBOR")
}

/// Decode one item that must fill `data` exactly.
pub fn decode(data: &[u8]) -> Result<Value<'_>, AttestError> {
    let (v, rest) = item(data, 0)?;
    if !rest.is_empty() {
        return Err(bad());
    }
    Ok(v)
}

fn take(data: &[u8], n: u64) -> Result<(&[u8], &[u8]), AttestError> {
    let n = usize::try_from(n).map_err(|_| bad())?;
    if data.len() < n {
        return Err(bad());
    }
    Ok(data.split_at(n))
}

fn argument(info: u8, data: &[u8]) -> Result<(u64, &[u8]), AttestError> {
    let n = match info {
        0..=23 => return Ok((info as u64, data)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(bad()),
    };
    let (b, rest) = take(data, n)?;
    let v = b.iter().fold(0u64, |acc, x| (acc << 8) | *x as u64);
    // Shortest form only, so one object has one encoding.
    let min = match n {
        1 => 24,
        2 => 0x100,
        4 => 0x1_0000,
        _ => 0x1_0000_0000,
    };
    if v < min {
        return Err(bad());
    }
    Ok((v, rest))
}

fn item(data: &[u8], depth: usize) -> Result<(Value<'_>, &[u8]), AttestError> {
    if depth > MAX_DEPTH {
        return Err(bad());
    }
    let (&head, rest) = data.split_first().ok_or_else(bad)?;
    let (major, info) = (head >> 5, head & 0x1f);
    let (arg, rest) = argument(info, rest)?;
    match major {
        0 => Ok((Value::Uint(arg), rest)),
        1 => Ok((Value::Nint(arg), rest)),
        2 => {
            let (b, rest) = take(rest, arg)?;
            Ok((Value::Bytes(b), rest))
        }
        3 => {
            let (b, rest) = take(rest, arg)?;
            Ok((Value::Text(std::str::from_utf8(b).map_err(|_| bad())?), rest))
        }
        4 => {
            if arg > MAX_ITEMS {
                return Err(bad());
            }
            let mut rest = rest;
            let mut items = Vec::with_capacity(arg as usize);
            for _ in 0..arg {
                let (v, r) = item(rest, depth + 1)?;
                items.push(v);
                rest = r;
            }
            Ok((Value::Array(items), rest))
        }
        5 => {
            if arg > MAX_ITEMS {
                return Err(bad());
            }
            let mut rest = rest;
            let mut items: Vec<(Value, Value)> = Vec::with_capacity(arg as usize);
            for _ in 0..arg {
                let (k, r) = item(rest, depth + 1)?;
                let (v, r) = item(r, depth + 1)?;
                if items.iter().any(|(e, _)| *e == k) {
                    return Err(bad());
                }
                items.push((k, v));
                rest = r;
            }
            Ok((Value::Map(items), rest))
        }
        7 if info < 24 => Ok((Value::Simple(info), rest)),
        _ => Err(bad()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_maps_arrays_and_strings() {
        // {"a": [1, -2, h'0102'], "b": "x"}
        let d = [0xa2, 0x61, b'a', 0x83, 0x01, 0x21, 0x42, 1, 2, 0x61, b'b', 0x61, b'x'];
        let v = decode(&d).unwrap();
        assert_eq!(
            v.get("a"),
            Some(&Value::Array(vec![Value::Uint(1), Value::Nint(1), Value::Bytes(&[1, 2])]))
        );
        assert_eq!(v.get("b"), Some(&Value::Text("x")));
    }

    #[test]
    fn refuses_what_app_attest_never_sends() {
        for d in [
            &[0x5f, 0x41, 0, 0xff][..], // indefinite bytes
            &[0xc0, 0x00],              // tag
            &[0xfa, 0, 0, 0, 0],        // float
            &[0x18, 0x05],              // non-shortest integer
            &[0x42, 0x01],              // short byte string
            &[0xa2, 0x61, b'a', 1, 0x61, b'a', 2], // duplicate key
            &[0x01, 0x02],              // trailing bytes
        ] {
            assert!(decode(d).is_err(), "{d:02x?}");
        }
        let mut deep = vec![0x81u8; 20];
        deep.push(0);
        assert!(decode(&deep).is_err());
    }
}
