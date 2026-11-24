/// A minimal standalone VHDX header and metadata for offline validation tests.
pub fn standalone() -> Vec<u8> {
    let mut disk=vec![0;0x50400];
    disk[..8].copy_from_slice(b"vhdxfile");
    disk[0x10000..0x10004].copy_from_slice(b"head");
    disk[0x20000..0x20004].copy_from_slice(b"head");
    let region=&mut disk[0x30000..0x40000];
    region[..4].copy_from_slice(b"regi"); region[8]=1;
    region[16..32].copy_from_slice(&[0x06,0xa2,0x7c,0x8b,0x90,0x47,0x9a,0x4b,0xb8,0xfe,0x57,0x5f,0x05,0x0f,0x88,0x6e]);
    region[32..40].copy_from_slice(&0x50000u64.to_le_bytes());
    region[40..44].copy_from_slice(&1024u32.to_le_bytes());
    let meta=&mut disk[0x50000..]; meta[..8].copy_from_slice(b"metadata"); meta[10]=1;
    meta[32..48].copy_from_slice(&[0x37,0x67,0xa1,0xca,0x36,0xfa,0x43,0x4d,0xb3,0xb6,0x33,0xf0,0xaa,0x44,0xe7,0x6b]);
    meta[48]=128; meta[52]=8;
    disk
}
