// SOCKS5 学習用修正版 配列でそのまま扱う実装コード
// ここで各種クレートを読み込みます
use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::thread;

fn main() -> io::Result<()> {
    // 1) リスナーを立てる
    // 穴埋め課題1: バインドするポートを指定してください。
    // user01が割り当てられている皆さんは0.0.0.0:1080を指定してください。（例：TcpListener::bind("0.0.0.0:1080")?;）
    // user02が割り当てられている皆さんは0.0.0.0:8080を指定してください。
    // user03が割り当てられている皆さんは0.0.0.0:8081を指定してください。
    // user04が割り当てられている皆さんは0.0.0.0:8082を指定してください。
    let listener = TcpListener::bind("ここを穴埋め")?;
    println!("SOCKS5 proxy running on {}", listener.local_addr()?);

    for incoming in listener.incoming() {
        match incoming {
            Ok(mut client) => {
                thread::spawn(move || {
                    if let Err(e) = handle_client_inline(&mut client) {
                        eprintln!("client error: {e}");
                        let _ = client.shutdown(Shutdown::Both);
                    }
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
    Ok(())
}

fn handle_client_inline(client: &mut TcpStream) -> io::Result<()> {
    // 2) Greeting を読む: [VER, NMETHODS, METHODS]
    let mut head2 = [0u8; 2];
    client.read_exact(&mut head2)?; // VER, NMETHODS
    let ver = head2[0];
    let nmethods = head2[1] as usize;
    if ver != 0x05 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("unsupported version: {ver}"),
        ));
    }

    let mut methods = vec![0u8; nmethods];
    if nmethods > 0 {
        client.read_exact(&mut methods)?;
    }
    println!("methods offered: {:?}", methods);

    // 3) METHOD 選択（No Auth があれば採用。なければ 0xFF）
    let chosen = if methods.iter().any(|&m| m == 0x00) {
        //穴埋め課題2: ここの条件分岐の中に、NO AUTHENTICATION REQUIREDの場合の適切な16進数を入れてください。（例：0x01）ヒント: 19ページ
        ここを穴埋め
    } else {
        0xFF
    };
    let selection = vec![0x05, chosen];
    client.write_all(&selection)?;
    client.flush()?;
    if chosen == 0xFF {
        return Err(io::Error::new(ErrorKind::Other, "no acceptable method"));
    }

    // 4) Request を読む: [VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
    let mut req_hdr = [0u8; 4];
    client.read_exact(&mut req_hdr)?;
    let ver = req_hdr[0];
    let cmd = req_hdr[1];
    let rsv = req_hdr[2];
    let atyp = req_hdr[3];
    if ver != 0x05 || rsv != 0x00 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "malformed request header",
        ));
    }

    if cmd != 0x01 {
        // CONNECT 以外は未対応
        // 失敗応答（Command not supported = 0x07）を配列で作成
        let mut rep = vec![0x05, 0x07, 0x00, 0x01]; // [VER, REP, RSV, ATYP(IPv4)]
        rep.extend_from_slice(&[0, 0, 0, 0]); // BND.ADDR
        rep.extend_from_slice(&[0, 0]); // BND.PORT
        client.write_all(&rep)?;
        client.flush()?;
        return Err(io::Error::new(
            ErrorKind::Other,
            "only CONNECT is supported",
        ));
    }

    // 5) DST.ADDR と DST.PORT の読み取り（ATYPに応じて可変長）
    enum Dst {
        V4([u8; 4], u16),
        V6([u8; 16], u16),
        Domain(String, u16),
    }

    let dst = match atyp {
        0x01 => {
            // IPv4
            let mut ip4 = [0u8; ここを穴埋め]; //穴埋め課題3: IPv4アドレスを読み込む適切な長さの空配列を作ってください。（例：let mut ip4 = [0u8; 1];）ヒント: 21ページ
            client.read_exact(&mut ip4)?;
            let mut p = [0u8; 2];
            client.read_exact(&mut p)?;
            let port = u16::from_be_bytes(p);
            Dst::V4(ip4, port)
        }
        0x03 => {
            // DOMAIN
            let mut len = [0u8; 1];
            client.read_exact(&mut len)?;
            let mut name = vec![0u8; len[0] as usize];
            if !name.is_empty() {
                client.read_exact(&mut name)?;
            }
            let mut p = [0u8; 2];
            client.read_exact(&mut p)?;
            let port = u16::from_be_bytes(p);
            let host = String::from_utf8_lossy(&name).into_owned();
            Dst::Domain(host, port)
        }
        0x04 => {
            // IPv6
            let mut ip6 = [0u8; ここを穴埋め]; //穴埋め課題4: IPv6アドレスを読み込む適切な長さの空配列を作ってください。（例：let mut ip6 = [0u8; 1];）ヒント: 21ページ
            client.read_exact(&mut ip6)?;
            let mut p = [0u8; 2];
            client.read_exact(&mut p)?;
            let port = u16::from_be_bytes(p);
            Dst::V6(ip6, port)
        }
        other => {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("unsupported ATYP: 0x{other:02X}"),
            ));
        }
    };

    // 6) 宛先へ TCP 接続

    // ログ（要求された宛先）を表示
    let requested = match &dst {
        Dst::V4(ip, port) => format!("{}.{}.{}.{}:{}", ip[0], ip[1], ip[2], ip[3], port),
        Dst::V6(ip, port) => format!("[{}]:{}", Ipv6Addr::from(*ip), port),
        Dst::Domain(host, port) => format!("{}:{}", host, port),
    };
    println!("Requested destination: {requested}");

    let remote = match &dst {
        Dst::V4(ip, port) => {
            let addr =
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])), *port);
            TcpStream::connect(addr)
        }
        Dst::V6(ip, port) => {
            let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*ip)), *port);
            TcpStream::connect(addr)
        }
        Dst::Domain(host, port) => TcpStream::connect((host.as_str(), *port)),
    };

    let mut remote = match remote {
        Ok(s) => s,
        Err(e) => {
            // 失敗時は General failure (0x01) を返す
            let mut rep = vec![0x05, 0x01, 0x00, 0x01];
            rep.extend_from_slice(&[0, 0, 0, 0]);
            rep.extend_from_slice(&[0, 0]);
            let _ = client.write_all(&rep);
            let _ = client.flush();
            return Err(e);
        }
    };

    // 7) 成功応答: [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
    if let Ok(peer) = remote.peer_addr() {
        println!("Connected to destination: {peer}");
    }
    let bound_addr = remote
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    println!("Bound local address: {bound_addr}");

    // 順に push し、ATYP は実アドレス種別で選択
    let mut response = Vec::with_capacity(4 + 16 + 2);
    response.push(ここを穴埋め); // 穴埋め課題5: Responseの配列にVERを入れてみましょう。適切な16進数を入力してください。（例：response.push(0x01)）ヒント: 22ページ
    response.push(ここを穴埋め); // 穴埋め課題6: Responseの配列にsucceededのときのREPを入れてみましょう。適切な16進数を入力してください。（例：response.push(0x01)）ヒント: 22ページ
    response.push(ここを穴埋め); // 穴埋め課題7: Responseの配列にRSVを入れてみましょう。適切な16進数を入力してください。（例：response.push(0x01)）ヒント: 22ページ

    match bound_addr {
        SocketAddr::V4(a) => {
            response.push(ここを穴埋め); //穴埋め課題8: Responseの配列にIPv4のときのATYPを入れてみましょう。適切な16進数を入力してください。（例：response.push(0x01)）ヒント: 22ページ
            response.extend_from_slice(&a.ip().octets());
            response.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            response.push(ここを穴埋め); //穴埋め課題9: Responseの配列にIPv6のときのATYPを入れてみましょう。適切な16進数を入力してください。（例：response.push(0x01)）ヒント: 22ページ
            response.extend_from_slice(&a.ip().octets());
            response.extend_from_slice(&a.port().to_be_bytes());
        }
    }

    client.write_all(&response)?;
    client.flush()?;

    // 8) 転送部分
    let mut c_read = client.try_clone()?;
    let mut r_write = remote.try_clone()?;
    let forward = thread::spawn(move || -> io::Result<()> {
        let n = io::copy(&mut c_read, &mut r_write)?;
        println!("client -> remote: {n} bytes");
        let _ = r_write.shutdown(Shutdown::Write);
        let _ = c_read.shutdown(Shutdown::Read);
        Ok(())
    });

    let n = io::copy(&mut remote, client)?;
    println!("remote -> client: {n} bytes");
    let _ = client.shutdown(Shutdown::Write);
    let _ = remote.shutdown(Shutdown::Read);

    match forward.join() {
        Ok(res) => res,
        Err(_) => Err(io::Error::new(ErrorKind::Other, "forward thread panicked")),
    }
}