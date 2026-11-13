/// Canonical AWS Nitro Enclaves Root Certificate (G1)
/// Subject: C=US, O=Amazon, OU=AWS, CN=aws.nitro-enclaves
/// Validity: 2019-10-28 to 2049-10-28
pub const AWS_NITRO_ROOT_CA_SHA512_HEX: &str = "da980c3a9043b6c384b12028bbf1d8528e8d407e929ba6e1730cb6b0b6b06823124e15687533a68b48990226545d71db459177de8f20fd43ea100232e5a68cd3";
pub const AWS_NITRO_ROOT_CA_SHA384_HEX: &str = "0a2a94444eaed2a0a584ec419284e645777bc81864268d33104d1c9796e824fbdc49a7b4d94ddc0b5a98ccb9e0cde50d";
pub const AWS_NITRO_ROOT_CA_SHA256_HEX: &str = "641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b";

pub const AWS_NITRO_ROOT_CA_SHA512: [u8; 64] = [
    0xda, 0x98, 0x0c, 0x3a, 0x90, 0x43, 0xb6, 0xc3,
    0x84, 0xb1, 0x20, 0x28, 0xbb, 0xf1, 0xd8, 0x52,
    0x8e, 0x8d, 0x40, 0x7e, 0x92, 0x9b, 0xa6, 0xe1,
    0x73, 0x0c, 0xb6, 0xb0, 0xb6, 0xb0, 0x68, 0x23,
    0x12, 0x4e, 0x15, 0x68, 0x75, 0x33, 0xa6, 0x8b,
    0x48, 0x99, 0x02, 0x26, 0x54, 0x5d, 0x71, 0xdb,
    0x45, 0x91, 0x77, 0xde, 0x8f, 0x20, 0xfd, 0x43,
    0xea, 0x10, 0x02, 0x32, 0xe5, 0xa6, 0x8c, 0xd3,
];

pub const AWS_NITRO_ROOT_CA_DER: [u8; 533] = [
    0x30, 0x82, 0x02, 0x11, 0x30, 0x82, 0x01, 0x96, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x11, 0x00, 0xf9, 0x31, 0x75, 0x68, 0x1b, 0x90, 0xaf, 0xe1,
    0x1d, 0x46, 0xcc, 0xb4, 0xe4, 0xe7, 0xf8, 0x56, 0x30, 0x0a, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x30, 0x49, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
    0x0f, 0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x41, 0x6d,
    0x61, 0x7a, 0x6f, 0x6e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04,
    0x0b, 0x0c, 0x03, 0x41, 0x57, 0x53, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x12, 0x61, 0x77, 0x73, 0x2e, 0x6e, 0x69, 0x74,
    0x72, 0x6f, 0x2d, 0x65, 0x6e, 0x63, 0x6c, 0x61, 0x76, 0x65, 0x73, 0x30,
    0x1e, 0x17, 0x0d, 0x31, 0x39, 0x31, 0x30, 0x32, 0x38, 0x31, 0x33, 0x32,
    0x38, 0x30, 0x35, 0x5a, 0x17, 0x0d, 0x34, 0x39, 0x31, 0x30, 0x32, 0x38,
    0x31, 0x34, 0x32, 0x38, 0x30, 0x35, 0x5a, 0x30, 0x49, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0f,
    0x30, 0x0d, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x06, 0x41, 0x6d, 0x61,
    0x7a, 0x6f, 0x6e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0b,
    0x0c, 0x03, 0x41, 0x57, 0x53, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x0c, 0x12, 0x61, 0x77, 0x73, 0x2e, 0x6e, 0x69, 0x74, 0x72,
    0x6f, 0x2d, 0x65, 0x6e, 0x63, 0x6c, 0x61, 0x76, 0x65, 0x73, 0x30, 0x76,
    0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
    0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0xfc, 0x02,
    0x54, 0xeb, 0xa6, 0x08, 0xc1, 0xf3, 0x68, 0x70, 0xe2, 0x9a, 0xda, 0x90,
    0xbe, 0x46, 0x38, 0x32, 0x92, 0x73, 0x6e, 0x89, 0x4b, 0xff, 0xf6, 0x72,
    0xd9, 0x89, 0x44, 0x4b, 0x50, 0x51, 0xe5, 0x34, 0xa4, 0xb1, 0xf6, 0xdb,
    0xe3, 0xc0, 0xbc, 0x58, 0x1a, 0x32, 0xb7, 0xb1, 0x76, 0x07, 0x0e, 0xde,
    0x12, 0xd6, 0x9a, 0x3f, 0xea, 0x21, 0x1b, 0x66, 0xe7, 0x52, 0xcf, 0x7d,
    0xd1, 0xdd, 0x09, 0x5f, 0x6f, 0x13, 0x70, 0xf4, 0x17, 0x08, 0x43, 0xd9,
    0xdc, 0x10, 0x01, 0x21, 0xe4, 0xcf, 0x63, 0x01, 0x28, 0x09, 0x66, 0x44,
    0x87, 0xc9, 0x79, 0x62, 0x84, 0x30, 0x4d, 0xc5, 0x3f, 0xf4, 0xa3, 0x42,
    0x30, 0x40, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
    0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x1d, 0x06, 0x03, 0x55,
    0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x90, 0x25, 0xb5, 0x0d, 0xd9, 0x05,
    0x47, 0xe7, 0x96, 0xc3, 0x96, 0xfa, 0x72, 0x9d, 0xcf, 0x99, 0xa9, 0xdf,
    0x4b, 0x96, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff,
    0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86,
    0x48, 0xce, 0x3d, 0x04, 0x03, 0x03, 0x03, 0x69, 0x00, 0x30, 0x66, 0x02,
    0x31, 0x00, 0xa3, 0x7f, 0x2f, 0x91, 0xa1, 0xc9, 0xbd, 0x5e, 0xe7, 0xb8,
    0x62, 0x7c, 0x16, 0x98, 0xd2, 0x55, 0x03, 0x8e, 0x1f, 0x03, 0x43, 0xf9,
    0x5b, 0x63, 0xa9, 0x62, 0x8c, 0x3d, 0x39, 0x80, 0x95, 0x45, 0xa1, 0x1e,
    0xbc, 0xbf, 0x2e, 0x3b, 0x55, 0xd8, 0xae, 0xee, 0x71, 0xb4, 0xc3, 0xd6,
    0xad, 0xf3, 0x02, 0x31, 0x00, 0xa2, 0xf3, 0x9b, 0x16, 0x05, 0xb2, 0x70,
    0x28, 0xa5, 0xdd, 0x4b, 0xa0, 0x69, 0xb5, 0x01, 0x6e, 0x65, 0xb4, 0xfb,
    0xde, 0x8f, 0xe0, 0x06, 0x1d, 0x6a, 0x53, 0x19, 0x7f, 0x9c, 0xda, 0xf5,
    0xd9, 0x43, 0xbc, 0x61, 0xfc, 0x2b, 0xeb, 0x03, 0xcb, 0x6f, 0xee, 0x8d,
    0x23, 0x02, 0xf3, 0xdf, 0xf6,
];

pub const AWS_NITRO_ROOT_CA_SHA384: [u8; 48] = [
    0x0a, 0x2a, 0x94, 0x44, 0x4e, 0xae, 0xd2, 0xa0,
    0xa5, 0x84, 0xec, 0x41, 0x92, 0x84, 0xe6, 0x45,
    0x77, 0x7b, 0xc8, 0x18, 0x64, 0x26, 0x8d, 0x33,
    0x10, 0x4d, 0x1c, 0x97, 0x96, 0xe8, 0x24, 0xfb,
    0xdc, 0x49, 0xa7, 0xb4, 0xd9, 0x4d, 0xdc, 0x0b,
    0x5a, 0x98, 0xcc, 0xb9, 0xe0, 0xcd, 0xe5, 0x0d,
];

/// Validates whether a DER-encoded X.509 certificate strictly matches the
/// AWS Nitro Enclaves Root CA in constant time.
#[inline]
pub fn matches_root_ca(der: &[u8]) -> bool {
    if der.len() != AWS_NITRO_ROOT_CA_DER.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in der.iter().zip(AWS_NITRO_ROOT_CA_DER.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

use crate::crypto::{ecdsa_p384_verify, P384Point};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509Error {
    MalformedDer,
    UnsupportedAlgorithm,
    InvalidPublicKey,
    InvalidValidityPeriod,
    ExpiredOrNotYetValid,
    ChainDepthViolation,
    RootCaMismatch,
    IssuerSubjectMismatch,
    SignatureVerificationFailed,
    BasicConstraintsViolation,
}

/// Constant-time comparison of two arbitrary byte slices.
#[inline]
pub fn ct_bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

struct DerReader<'a> {
    buf: &'a [u8],
    offset: usize,
}

impl<'a> DerReader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    const fn is_empty(&self) -> bool {
        self.offset >= self.buf.len()
    }

    fn peek_tag(&self) -> Option<u8> {
        self.buf.get(self.offset).copied()
    }

    /// Reads one ASN.1 DER TLV element, returning `(tag, full_tlv_slice, value_slice)`.
    fn read_tlv(&mut self) -> Result<(u8, &'a [u8], &'a [u8]), X509Error> {
        let start = self.offset;
        let tag = *self.buf.get(self.offset).ok_or(X509Error::MalformedDer)?;
        self.offset += 1;

        let len_first = *self.buf.get(self.offset).ok_or(X509Error::MalformedDer)?;
        self.offset += 1;

        let content_len: usize = if (len_first & 0x80) == 0 {
            usize::from(len_first)
        } else {
            let num_len_bytes = usize::from(len_first & 0x7f);
            if num_len_bytes == 0 || num_len_bytes > 4 {
                return Err(X509Error::MalformedDer);
            }
            let mut acc = 0usize;
            let mut i = 0;
            while i < num_len_bytes {
                let b = *self.buf.get(self.offset).ok_or(X509Error::MalformedDer)?;
                if i == 0 && b == 0 {
                    // Reject non-minimal DER length encoding
                    return Err(X509Error::MalformedDer);
                }
                self.offset += 1;
                acc = (acc << 8) | usize::from(b);
                i += 1;
            }
            if acc < 128 {
                // Reject non-minimal long-form length for < 128 bytes
                return Err(X509Error::MalformedDer);
            }
            acc
        };

        let val_start = self.offset;
        let val_end = val_start
            .checked_add(content_len)
            .ok_or(X509Error::MalformedDer)?;
        if val_end > self.buf.len() {
            return Err(X509Error::MalformedDer);
        }
        self.offset = val_end;
        Ok((tag, &self.buf[start..val_end], &self.buf[val_start..val_end]))
    }

    fn expect_tag(&mut self, expected_tag: u8) -> Result<(&'a [u8], &'a [u8]), X509Error> {
        let (tag, full, val) = self.read_tlv()?;
        if tag != expected_tag {
            return Err(X509Error::MalformedDer);
        }
        Ok((full, val))
    }
}

/// OID 1.2.840.10045.4.3.3 (`ecdsa-with-SHA384`) DER value bytes
const OID_ECDSA_WITH_SHA384: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
/// OID 1.2.840.10045.2.1 (`id-ecPublicKey`) DER value bytes
const OID_ID_EC_PUBLIC_KEY: [u8; 7] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// OID 1.3.132.0.34 (`secp384r1`) DER value bytes
const OID_SECP384R1: [u8; 5] = [0x2b, 0x81, 0x04, 0x00, 0x22];
/// OID 2.5.29.19 (`BasicConstraints`) DER value bytes
const OID_BASIC_CONSTRAINTS: [u8; 3] = [0x55, 0x1d, 0x13];
/// OID 2.5.29.15 (`KeyUsage`) DER value bytes
const OID_KEY_USAGE: [u8; 3] = [0x55, 0x1d, 0x0f];

fn parse_ecdsa_sha384_alg_id(alg_seq_val: &[u8]) -> Result<(), X509Error> {
    let mut r = DerReader::new(alg_seq_val);
    let (_, oid_val) = r.expect_tag(0x06)?;
    if oid_val != OID_ECDSA_WITH_SHA384 {
        return Err(X509Error::UnsupportedAlgorithm);
    }
    // RFC 5758 §3.2: parameters MUST be omitted for ecdsa-with-SHA384 (some encoders emit NULL)
    if !r.is_empty() {
        let (_, null_val) = r.expect_tag(0x05)?;
        if !null_val.is_empty() || !r.is_empty() {
            return Err(X509Error::MalformedDer);
        }
    }
    Ok(())
}

fn parse_2_digits(b: &[u8]) -> Result<u64, X509Error> {
    if b.len() < 2 || !b[0].is_ascii_digit() || !b[1].is_ascii_digit() {
        return Err(X509Error::InvalidValidityPeriod);
    }
    Ok(u64::from(b[0] - b'0') * 10 + u64::from(b[1] - b'0'))
}

fn parse_4_digits(b: &[u8]) -> Result<u64, X509Error> {
    let hi = parse_2_digits(&b[0..2])?;
    let lo = parse_2_digits(&b[2..4])?;
    Ok(hi * 100 + lo)
}

const fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

#[inline(never)]
fn parse_x509_time(tag: u8, val: &[u8]) -> Result<u64, X509Error> {
    let (year, rest) = match tag {
        0x17 => {
            // UTCTime: YYMMDDHHMMSSZ (13 bytes)
            if val.len() != 13 || val[12] != b'Z' {
                return Err(X509Error::InvalidValidityPeriod);
            }
            let yy = parse_2_digits(&val[0..2])?;
            let full_year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (full_year, &val[2..12])
        }
        0x18 => {
            // GeneralizedTime: YYYYMMDDHHMMSSZ (15 bytes)
            if val.len() != 15 || val[14] != b'Z' {
                return Err(X509Error::InvalidValidityPeriod);
            }
            let full_year = parse_4_digits(&val[0..4])?;
            (full_year, &val[4..14])
        }
        _ => return Err(X509Error::InvalidValidityPeriod),
    };

    if !(1970..=9999).contains(&year) {
        return Err(X509Error::InvalidValidityPeriod);
    }
    let month = parse_2_digits(&rest[0..2])?;
    let day = parse_2_digits(&rest[2..4])?;
    let hour = parse_2_digits(&rest[4..6])?;
    let minute = parse_2_digits(&rest[6..8])?;
    let second = parse_2_digits(&rest[8..10])?;

    if !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 60 {
        return Err(X509Error::InvalidValidityPeriod);
    }

    let mdays: [u64; 13] = [
        0,
        31,
        if is_leap_year(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let m_idx = usize::try_from(month).map_err(|_| X509Error::InvalidValidityPeriod)?;
    if day == 0 || day > mdays[m_idx] {
        return Err(X509Error::InvalidValidityPeriod);
    }

    let mut days = 0u64;
    let mut y = 1970u64;
    while y < year {
        days += if is_leap_year(y) { 366 } else { 365 };
        y += 1;
    }
    let mut m = 1usize;
    while m < m_idx {
        days += mdays[m];
        m += 1;
    }
    days += day - 1;
    Ok(days * 86_400 + hour * 3600 + minute * 60 + second)
}

#[inline(never)]
fn parse_der_ecdsa_sig(sig_seq_val: &[u8]) -> Result<([u8; 48], [u8; 48]), X509Error> {
    let mut r = DerReader::new(sig_seq_val);
    let (_, r_int) = r.expect_tag(0x02)?;
    let (_, s_int) = r.expect_tag(0x02)?;
    if !r.is_empty() {
        return Err(X509Error::MalformedDer);
    }

    let r_bytes = decode_der_positive_int_48(r_int)?;
    let s_bytes = decode_der_positive_int_48(s_int)?;
    Ok((r_bytes, s_bytes))
}

fn decode_der_positive_int_48(raw: &[u8]) -> Result<[u8; 48], X509Error> {
    if raw.is_empty() || (raw[0] & 0x80) != 0 {
        return Err(X509Error::MalformedDer);
    }
    let trimmed = if raw.len() > 1 && raw[0] == 0x00 {
        if (raw[1] & 0x80) == 0 {
            // Non-minimal leading zero padding in ASN.1 INTEGER
            return Err(X509Error::MalformedDer);
        }
        &raw[1..]
    } else {
        raw
    };
    if trimmed.is_empty() || trimmed.len() > 48 {
        return Err(X509Error::MalformedDer);
    }
    let mut out = [0u8; 48];
    out[48 - trimmed.len()..].copy_from_slice(trimmed);
    Ok(out)
}

pub struct ParsedX509Cert<'a> {
    pub tbs_der: &'a [u8],
    pub issuer_der: &'a [u8],
    pub subject_der: &'a [u8],
    pub not_before: u64,
    pub not_after: u64,
    pub public_key: P384Point,
    pub is_ca: bool,
    pub path_len_constraint: Option<u64>,
    pub key_cert_sign: Option<bool>,
    pub sig_r: [u8; 48],
    pub sig_s: [u8; 48],
}

#[inline(never)]
fn parse_x509_spki(spki_val: &[u8]) -> Result<P384Point, X509Error> {
    let mut spki_r = DerReader::new(spki_val);
    let (_, spki_alg_val) = spki_r.expect_tag(0x30)?;
    let (_, spki_bitstr) = spki_r.expect_tag(0x03)?;
    if !spki_r.is_empty() {
        return Err(X509Error::MalformedDer);
    }
    let mut spki_alg_r = DerReader::new(spki_alg_val);
    let (_, key_oid) = spki_alg_r.expect_tag(0x06)?;
    let (_, curve_oid) = spki_alg_r.expect_tag(0x06)?;
    if !spki_alg_r.is_empty()
        || key_oid != OID_ID_EC_PUBLIC_KEY
        || curve_oid != OID_SECP384R1
    {
        return Err(X509Error::InvalidPublicKey);
    }
    if spki_bitstr.len() != 98 || spki_bitstr[0] != 0 {
        return Err(X509Error::InvalidPublicKey);
    }
    P384Point::from_uncompressed_bytes(&spki_bitstr[1..]).ok_or(X509Error::InvalidPublicKey)
}

#[inline(never)]
fn parse_x509_extensions(
    exts_seq: &[u8],
) -> Result<(bool, Option<u64>, Option<bool>), X509Error> {
    let mut is_ca = false;
    let mut path_len_constraint: Option<u64> = None;
    let mut key_cert_sign: Option<bool> = None;

    let mut exts_r = DerReader::new(exts_seq);
    while !exts_r.is_empty() {
        let (_, ext_val) = exts_r.expect_tag(0x30)?;
        let mut er = DerReader::new(ext_val);
        let (_, ext_oid) = er.expect_tag(0x06)?;
        if er.peek_tag() == Some(0x01) {
            let (_, crit_val) = er.expect_tag(0x01)?;
            if crit_val.len() != 1 {
                return Err(X509Error::MalformedDer);
            }
        }
        let (_, ext_octets) = er.expect_tag(0x04)?;
        if !er.is_empty() {
            return Err(X509Error::MalformedDer);
        }

        if ext_oid == OID_BASIC_CONSTRAINTS {
            let mut bcr = DerReader::new(ext_octets);
            let (_, bc_seq) = bcr.expect_tag(0x30)?;
            if !bcr.is_empty() {
                return Err(X509Error::MalformedDer);
            }
            let mut bc_inner = DerReader::new(bc_seq);
            if bc_inner.peek_tag() == Some(0x01) {
                let (_, bool_val) = bc_inner.expect_tag(0x01)?;
                if bool_val.len() != 1 {
                    return Err(X509Error::MalformedDer);
                }
                is_ca = bool_val[0] != 0;
            }
            if bc_inner.peek_tag() == Some(0x02) {
                let (_, plen_val) = bc_inner.expect_tag(0x02)?;
                if plen_val.is_empty() || plen_val.len() > 4 || (plen_val[0] & 0x80) != 0 {
                    return Err(X509Error::MalformedDer);
                }
                let mut plen = 0u64;
                for &b in plen_val {
                    plen = (plen << 8) | u64::from(b);
                }
                path_len_constraint = Some(plen);
            }
            if !bc_inner.is_empty() {
                return Err(X509Error::MalformedDer);
            }
        } else if ext_oid == OID_KEY_USAGE {
            let mut kur = DerReader::new(ext_octets);
            let (_, ku_bits) = kur.expect_tag(0x03)?;
            if !kur.is_empty() || ku_bits.len() < 2 || ku_bits[0] > 7 {
                return Err(X509Error::MalformedDer);
            }
            key_cert_sign = Some((ku_bits[1] & 0x04) != 0);
        }
    }

    Ok((is_ca, path_len_constraint, key_cert_sign))
}

#[inline(never)]
fn parse_x509_validity(validity_val: &[u8]) -> Result<(u64, u64), X509Error> {
    let mut val_r = DerReader::new(validity_val);
    let (nb_tag, _, nb_val) = val_r.read_tlv()?;
    let (na_tag, _, na_val) = val_r.read_tlv()?;
    if !val_r.is_empty() {
        return Err(X509Error::MalformedDer);
    }
    let not_before = parse_x509_time(nb_tag, nb_val)?;
    let not_after = parse_x509_time(na_tag, na_val)?;
    if not_before > not_after {
        return Err(X509Error::InvalidValidityPeriod);
    }
    Ok((not_before, not_after))
}

struct ParsedTbsFields<'a> {
    issuer_der: &'a [u8],
    subject_der: &'a [u8],
    not_before: u64,
    not_after: u64,
    public_key: P384Point,
    is_ca: bool,
    path_len_constraint: Option<u64>,
    key_cert_sign: Option<bool>,
}

#[inline(never)]
fn parse_x509_tbs_body<'a>(
    tbs_val: &'a [u8],
    outer_alg_val: &[u8],
) -> Result<ParsedTbsFields<'a>, X509Error> {
    let mut tbs = DerReader::new(tbs_val);
    if tbs.peek_tag() == Some(0xa0) {
        let (_, ver_wrapper) = tbs.expect_tag(0xa0)?;
        let mut vr = DerReader::new(ver_wrapper);
        let (_, ver_int) = vr.expect_tag(0x02)?;
        if !vr.is_empty() || ver_int != [0x02] {
            return Err(X509Error::MalformedDer);
        }
    }

    let (_, serial_val) = tbs.expect_tag(0x02)?;
    if serial_val.is_empty() {
        return Err(X509Error::MalformedDer);
    }

    let (_, inner_alg_val) = tbs.expect_tag(0x30)?;
    if inner_alg_val != outer_alg_val {
        return Err(X509Error::MalformedDer);
    }

    let (issuer_der, _) = tbs.expect_tag(0x30)?;
    let (_, validity_val) = tbs.expect_tag(0x30)?;
    let (not_before, not_after) = parse_x509_validity(validity_val)?;
    let (subject_der, _) = tbs.expect_tag(0x30)?;
    let (_, spki_val) = tbs.expect_tag(0x30)?;
    let public_key = parse_x509_spki(spki_val)?;

    while let Some(tag) = tbs.peek_tag() {
        if tag == 0x81 || tag == 0x82 {
            let _ = tbs.read_tlv()?;
        } else {
            break;
        }
    }

    let (is_ca, path_len_constraint, key_cert_sign) = if tbs.peek_tag() == Some(0xa3) {
        let (_, ext_wrap) = tbs.expect_tag(0xa3)?;
        let mut ext_wrap_r = DerReader::new(ext_wrap);
        let (_, exts_seq) = ext_wrap_r.expect_tag(0x30)?;
        if !ext_wrap_r.is_empty() {
            return Err(X509Error::MalformedDer);
        }
        parse_x509_extensions(exts_seq)?
    } else {
        (false, None, None)
    };

    if !tbs.is_empty() {
        return Err(X509Error::MalformedDer);
    }

    Ok(ParsedTbsFields {
        issuer_der,
        subject_der,
        not_before,
        not_after,
        public_key,
        is_ca,
        path_len_constraint,
        key_cert_sign,
    })
}

#[inline(never)]
pub fn parse_x509_der(der: &[u8]) -> Result<ParsedX509Cert<'_>, X509Error> {
    let mut outer = DerReader::new(der);
    let (_, cert_seq) = outer.expect_tag(0x30)?;
    if !outer.is_empty() {
        return Err(X509Error::MalformedDer);
    }

    let mut cert_reader = DerReader::new(cert_seq);
    let (tbs_der, tbs_val) = cert_reader.expect_tag(0x30)?;
    let (_, outer_alg_val) = cert_reader.expect_tag(0x30)?;
    let (_, sig_bitstr_val) = cert_reader.expect_tag(0x03)?;
    if !cert_reader.is_empty() {
        return Err(X509Error::MalformedDer);
    }

    parse_ecdsa_sha384_alg_id(outer_alg_val)?;

    if sig_bitstr_val.len() < 2 || sig_bitstr_val[0] != 0 {
        return Err(X509Error::MalformedDer);
    }
    let mut sig_reader = DerReader::new(&sig_bitstr_val[1..]);
    let (_, sig_seq_val) = sig_reader.expect_tag(0x30)?;
    if !sig_reader.is_empty() {
        return Err(X509Error::MalformedDer);
    }
    let (sig_r, sig_s) = parse_der_ecdsa_sig(sig_seq_val)?;
    let tbs_fields = parse_x509_tbs_body(tbs_val, outer_alg_val)?;

    Ok(ParsedX509Cert {
        tbs_der,
        issuer_der: tbs_fields.issuer_der,
        subject_der: tbs_fields.subject_der,
        not_before: tbs_fields.not_before,
        not_after: tbs_fields.not_after,
        public_key: tbs_fields.public_key,
        is_ca: tbs_fields.is_ca,
        path_len_constraint: tbs_fields.path_len_constraint,
        key_cert_sign: tbs_fields.key_cert_sign,
        sig_r,
        sig_s,
    })
}

#[inline(never)]
fn verify_ca_cert_link<'a>(
    cert_der: &'a [u8],
    expected_issuer: Option<&[u8]>,
    issuer_pubkey: Option<&P384Point>,
    at_unix_secs: u64,
    remaining_path_len: &mut Option<u64>,
) -> Result<(&'a [u8], P384Point), X509Error> {
    let cert = parse_x509_der(cert_der)?;
    if !cert.is_ca || cert.key_cert_sign == Some(false) {
        return Err(X509Error::BasicConstraintsViolation);
    }
    if at_unix_secs < cert.not_before || at_unix_secs > cert.not_after {
        return Err(X509Error::ExpiredOrNotYetValid);
    }
    if let (Some(exp_iss), Some(iss_pk)) = (expected_issuer, issuer_pubkey) {
        if let Some(rem) = *remaining_path_len {
            if rem == 0 {
                return Err(X509Error::ChainDepthViolation);
            }
            *remaining_path_len = Some(rem - 1);
        }
        if cert.issuer_der != exp_iss {
            return Err(X509Error::IssuerSubjectMismatch);
        }
        if !ecdsa_p384_verify(iss_pk, cert.tbs_der, &cert.sig_r, &cert.sig_s) {
            return Err(X509Error::SignatureVerificationFailed);
        }
    } else {
        if cert.issuer_der != cert.subject_der {
            return Err(X509Error::IssuerSubjectMismatch);
        }
        if !ecdsa_p384_verify(&cert.public_key, cert.tbs_der, &cert.sig_r, &cert.sig_s) {
            return Err(X509Error::SignatureVerificationFailed);
        }
    }
    if let Some(limit) = cert.path_len_constraint {
        *remaining_path_len = Some(match *remaining_path_len {
            Some(cur) => cur.min(limit),
            None => limit,
        });
    }
    Ok((cert.subject_der, cert.public_key))
}

#[inline(never)]
fn verify_leaf_cert(
    leaf_der: &[u8],
    expected_issuer: &[u8],
    issuer_pubkey: &P384Point,
    at_unix_secs: u64,
) -> Result<P384Point, X509Error> {
    let leaf = parse_x509_der(leaf_der)?;
    if leaf.is_ca || leaf.key_cert_sign == Some(true) {
        return Err(X509Error::BasicConstraintsViolation);
    }
    if leaf.issuer_der != expected_issuer {
        return Err(X509Error::IssuerSubjectMismatch);
    }
    if at_unix_secs < leaf.not_before || at_unix_secs > leaf.not_after {
        return Err(X509Error::ExpiredOrNotYetValid);
    }
    if !ecdsa_p384_verify(issuer_pubkey, leaf.tbs_der, &leaf.sig_r, &leaf.sig_s) {
        return Err(X509Error::SignatureVerificationFailed);
    }
    Ok(leaf.public_key)
}

/// Validates a full X.509 certificate chain from `trusted_root_der` through
/// `cabundle` (`[root, intermediate_1, ...]`) to `leaf_der` at timestamp `at_unix_secs`.
/// Returns the verified leaf P-384 public key.
#[inline(never)]
pub fn verify_x509_chain(
    leaf_der: &[u8],
    cabundle: &[&[u8]],
    trusted_root_der: &[u8],
    at_unix_secs: u64,
) -> Result<P384Point, X509Error> {
    if cabundle.is_empty() || cabundle.len() > 8 {
        return Err(X509Error::ChainDepthViolation);
    }
    if !ct_bytes_eq(cabundle[0], trusted_root_der) {
        return Err(X509Error::RootCaMismatch);
    }

    let mut remaining_path_len: Option<u64> = None;
    let (mut current_issuer_subject, mut current_pubkey) =
        verify_ca_cert_link(cabundle[0], None, None, at_unix_secs, &mut remaining_path_len)?;

    let mut idx = 1usize;
    while idx < cabundle.len() {
        let (next_subj, next_pk) = verify_ca_cert_link(
            cabundle[idx],
            Some(current_issuer_subject),
            Some(&current_pubkey),
            at_unix_secs,
            &mut remaining_path_len,
        )?;
        current_issuer_subject = next_subj;
        current_pubkey = next_pk;
        idx += 1;
    }

    verify_leaf_cert(leaf_der, current_issuer_subject, &current_pubkey, at_unix_secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{sha384_digest, sha512_digest};

    #[test]
    fn test_aws_nitro_root_ca_cryptographic_self_signature_and_digests() {
        assert_eq!(sha384_digest(&AWS_NITRO_ROOT_CA_DER), AWS_NITRO_ROOT_CA_SHA384);
        assert_eq!(sha512_digest(&AWS_NITRO_ROOT_CA_DER), AWS_NITRO_ROOT_CA_SHA512);

        let parsed_res = parse_x509_der(&AWS_NITRO_ROOT_CA_DER);
        assert!(
            parsed_res.is_ok(),
            "Canonical AWS Nitro Root CA G1 DER must parse cleanly"
        );
        if let Ok(parsed) = parsed_res {
            assert!(parsed.is_ca);
            assert_eq!(parsed.not_before, 1_572_269_285);
            assert_eq!(parsed.not_after, 2_519_044_085);
            assert!(ecdsa_p384_verify(
                &parsed.public_key,
                parsed.tbs_der,
                &parsed.sig_r,
                &parsed.sig_s,
            ));
        }
    }
}
