//! Just enough DER to read Android's KeyDescription extension.

use crate::AttestError;

pub const CLASS_UNIVERSAL: u8 = 0;
pub const CLASS_CONTEXT: u8 = 2;

pub const BOOLEAN: u32 = 1;
pub const INTEGER: u32 = 2;
pub const OCTET_STRING: u32 = 4;
pub const ENUMERATED: u32 = 10;
pub const SEQUENCE: u32 = 16;
pub const SET: u32 = 17;

#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub class: u8,
    pub constructed: bool,
    pub tag: u32,
    pub value: &'a [u8],
}

fn bad(what: &'static str) -> AttestError {
    AttestError::Malformed(what)
}

/// Read one TLV; returns it and the bytes after it.
pub fn read(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), AttestError> {
    let mut i = 0;
    let b0 = *input.first().ok_or(bad("truncated tag"))?;
    i += 1;
    let class = b0 >> 6;
    let constructed = b0 & 0x20 != 0;
    let mut tag = (b0 & 0x1f) as u32;
    if tag == 0x1f {
        tag = 0;
        let mut n = 0;
        loop {
            let b = *input.get(i).ok_or(bad("truncated tag"))?;
            i += 1;
            n += 1;
            if n == 1 && b == 0x80 {
                return Err(bad("non-minimal tag"));
            }
            if n > 4 {
                return Err(bad("tag too large"));
            }
            tag = (tag << 7) | (b & 0x7f) as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let l0 = *input.get(i).ok_or(bad("truncated length"))?;
    i += 1;
    let len = if l0 < 0x80 {
        l0 as usize
    } else if l0 == 0x80 {
        return Err(bad("indefinite length"));
    } else {
        let n = (l0 & 0x7f) as usize;
        if n > 4 {
            return Err(bad("length too large"));
        }
        let mut len = 0usize;
        for _ in 0..n {
            let b = *input.get(i).ok_or(bad("truncated length"))?;
            i += 1;
            len = (len << 8) | b as usize;
        }
        len
    };
    let end = i.checked_add(len).ok_or(bad("length overflow"))?;
    let value = input.get(i..end).ok_or(bad("value past end"))?;
    Ok((Tlv { class, constructed, tag, value }, &input[end..]))
}

/// Read one TLV that must be the given universal type.
pub fn expect<'a>(input: &'a [u8], tag: u32) -> Result<(Tlv<'a>, &'a [u8]), AttestError> {
    let (t, rest) = read(input)?;
    if t.class != CLASS_UNIVERSAL || t.tag != tag {
        return Err(bad("unexpected type"));
    }
    if t.constructed != matches!(tag, SEQUENCE | SET) {
        return Err(bad("unexpected encoding"));
    }
    Ok((t, rest))
}

/// Every TLV in a constructed value.
pub fn items(mut value: &[u8]) -> Result<Vec<Tlv<'_>>, AttestError> {
    let mut out = Vec::new();
    while !value.is_empty() {
        let (t, rest) = read(value)?;
        out.push(t);
        value = rest;
    }
    Ok(out)
}

/// INTEGER or ENUMERATED content as i64.
pub fn int(t: &Tlv<'_>) -> Result<i64, AttestError> {
    if t.class != CLASS_UNIVERSAL || !(t.tag == INTEGER || t.tag == ENUMERATED) || t.constructed {
        return Err(bad("expected integer"));
    }
    let v = t.value;
    if v.is_empty() || v.len() > 8 {
        return Err(bad("integer size"));
    }
    let mut x: i64 = if v[0] & 0x80 != 0 { -1 } else { 0 };
    for b in v {
        x = (x << 8) | *b as i64;
    }
    Ok(x)
}

pub fn boolean(t: &Tlv<'_>) -> Result<bool, AttestError> {
    if t.class != CLASS_UNIVERSAL || t.tag != BOOLEAN || t.value.len() != 1 {
        return Err(bad("expected boolean"));
    }
    // DER says 0xff for true; some TEEs write 0x01.
    Ok(t.value[0] != 0)
}

pub fn octets<'a>(t: &Tlv<'a>) -> Result<&'a [u8], AttestError> {
    if t.class != CLASS_UNIVERSAL || t.tag != OCTET_STRING || t.constructed {
        return Err(bad("expected octet string"));
    }
    Ok(t.value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_tag_and_long_length() {
        // [704] EXPLICIT, constructed, context: 0xbf 0x85 0x40
        let mut v = vec![0xbf, 0x85, 0x40, 0x81, 0x80];
        v.extend(std::iter::repeat(0).take(128));
        let (t, rest) = read(&v).unwrap();
        assert_eq!((t.class, t.constructed, t.tag, t.value.len()), (CLASS_CONTEXT, true, 704, 128));
        assert!(rest.is_empty());
    }

    #[test]
    fn rejects_bad_encodings() {
        assert!(read(&[0x30, 0x80]).is_err()); // indefinite
        assert!(read(&[0x04, 0x05, 1, 2]).is_err()); // past end
        assert!(read(&[0x1f, 0x80, 0x01, 0x00]).is_err()); // non-minimal tag
        assert!(read(&[]).is_err());
    }

    #[test]
    fn integers() {
        let t = |v: &'static [u8]| Tlv { class: 0, constructed: false, tag: INTEGER, value: v };
        assert_eq!(int(&t(&[0x01])).unwrap(), 1);
        assert_eq!(int(&t(&[0xff])).unwrap(), -1);
        assert_eq!(int(&t(&[0x00, 0x80])).unwrap(), 128);
        assert_eq!(int(&t(&[0x03, 0x35, 0x2b])).unwrap(), 210_219);
        assert!(int(&t(&[])).is_err());
        assert!(int(&t(&[1; 9])).is_err());
    }
}
