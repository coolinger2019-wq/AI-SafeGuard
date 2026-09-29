#[test]
fn dbg_ja4_ext_input() {
    let sni = {
        let name = b"example.test";
        let mut d = vec![0x00, 0x0f];
        d.extend_from_slice(&[0x00, name.len() as u8]);
        d.extend_from_slice(name);
        d
    };
    let alpn = {
        let mut d = vec![0x00, 0x0e];
        d.push(2);
        d.extend_from_slice(b"h2");
        d.push(8);
        d.extend_from_slice(b"http/1.1");
        d
    };
    let rec = build_client_hello(
        0x0303,
        &[0x1301, 0x0a0a, 0x1302, 0xc02f],
        &[
            (0x0000, sni),
            (0x000a, vec![0x00, 0x02, 0x00, 0x1d]),
            (0x000b, vec![0x01, 0x00]),
            (0x000d, vec![0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01]),
            (0x0010, alpn),
            (0x002b, vec![0x00, 0x04, 0x03, 0x04, 0x03, 0x03]),
            (0x1a1a, vec![0x00]),
        ],
    );
    let ch = walk_client_hello(&rec).unwrap();
    for (t, d) in &ch.extensions {
        eprintln!("ext {t:04x} len {}", d.len());
    }
}
