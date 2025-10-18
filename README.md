# RFCを読んで実装してみよう！ハンズオン

座学ではRFCの概要を確認し、SOCKSのRFC読解に取り組んできました。ここからはハンズオンセッションに入ります。共通課題→中級課題（任意）→上級課題（任意）を通じて、レベルに応じて実装に挑戦していただけますと幸いです。

## 共通課題
RFCを読みながら簡単な穴埋めをし、SOCKSが実際に動く様子を確認し、Wiresharkでパケットを解析するまでの一連のフェーズを共通課題とします。

まずは、`src/basic.rs`をコピーし、事前課題で確認した`main.rs`にペーストして上書きしてください。最低限の機能を有したSOCKSは標準ライブラリだけで200行程度で実装できることがわかります。
そのうえで、以下の部分の穴埋めに取り組んでください。穴埋めが全て完了すると、実際に動作可能なSOCKS5プロキシが出来上がります。

穴埋め課題を通じて、座学で学習したMethod交渉 → Requests → Repliesのフローを実際にご体験ください。

穴埋め課題1: `main.rs` L7-32
```rust
fn main() -> io::Result<()> {
    // 1) リスナーを立てる
    // 穴埋め課題1: バインドするポートを指定してください。
    // user02が割り当てられている皆さんは0.0.0.0:1080を指定してください。（例：TcpListener::bind("0.0.0.0:1080")?;）
    // user03が割り当てられている皆さんは0.0.0.0:8080を指定してください。
    // user04が割り当てられている皆さんは0.0.0.0:8081を指定してください。
    // user05が割り当てられている皆さんは0.0.0.0:8082を指定してください。
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
```

穴埋め課題2: `main.rs` L53-65
```rust
    // 3) METHOD 選択（No Auth があれば採用。なければ 0xFF）
    let chosen = if methods.iter().any(|&m| m == 0x00) {
        //穴埋め課題2: ここの条件分岐の中に、NO AUTHENTICATION REQUIREDの場合の適切な16進数を入れてください。（例：0x01）ヒント: 20ページ
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
```

穴埋め課題3: `main.rs` L103-111
```rust
        0x01 => {
            // IPv4
            let mut ip4 = [0u8; ここを穴埋め]; //穴埋め課題3: IPv4アドレスを読み込む適切な長さの空配列を作ってください。（例：let mut ip4 = [0u8; 1];）ヒント: 22ページ
            client.read_exact(&mut ip4)?;
            let mut p = [0u8; 2];
            client.read_exact(&mut p)?;
            let port = u16::from_be_bytes(p);
            Dst::V4(ip4, port)
        }
```

穴埋め課題4: `main.rs` L126-134
```rust
        0x04 => {
            // IPv6
            let mut ip6 = [0u8; ここを穴埋め]; //穴埋め課題4: IPv6アドレスを読み込む適切な長さの空配列を作ってください。（例：let mut ip6 = [0u8; 1];）ヒント: 22ページ
            client.read_exact(&mut ip6)?;
            let mut p = [0u8; 2];
            client.read_exact(&mut p)?;
            let port = u16::from_be_bytes(p);
            Dst::V6(ip6, port)
        }
```

穴埋め課題5,6,7,8,9: `main.rs` L188-205
```rust
    // 順に push し、ATYP は実アドレス種別で選択
    let mut response = Vec::with_capacity(4 + 16 + 2);
    response.push(ここを穴埋め); // 穴埋め課題5: Responseの配列にVERを入れてみましょう。適切な16進数を入力してください。（例：response.push(0x01)）ヒント: 23ページ
    response.push(ここを穴埋め); // 穴埋め課題6: Responseの配列にsucceededのときのREPを入れてみましょう。適切な16進数を入力してください。（例：response.push(0x01)）ヒント: 23ページ
    response.push(ここを穴埋め); // 穴埋め課題7: Responseの配列にRSVを入れてみましょう。適切な16進数を入力してください。（例：response.push(0x01)）ヒント: 23ページ

    match bound_addr {
        SocketAddr::V4(a) => {
            response.push(ここを穴埋め); //穴埋め課題8: Responseの配列にIPv4のときのATYPを入れてみましょう。適切な16進数を入力してください。（例：response.push(0x01)）ヒント: 23ページ
            response.extend_from_slice(&a.ip().octets());
            response.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            response.push(ここを穴埋め); //穴埋め課題9: Responseの配列にIPv6のときのATYPを入れてみましょう。適切な16進数を入力してください。（例：response.push(0x01)）ヒント: 23ページ
            response.extend_from_slice(&a.ip().octets());
            response.extend_from_slice(&a.port().to_be_bytes());
        }
    }
```

穴埋めが完了したら、実際に実行してみましょう。
```shell-session
$ cargo run
```

ブラウザ（Firefoxを推奨）の「設定」→「ネットワーク設定」→「手動でプロキシを設定する」から、「SOCKSホスト」の欄に、割り当てられているIPアドレスを入力し、「ポート」の欄に割り当てられているポート番号を入力してください。あわせて、「SOCKS v5 を使用するときは DNS もプロキシーを使用する」にチェックを入れてください。（入れた場合と入れなかった場合の動作の違いを観察してみるのもよいです）

ここまでできたら、実際にSOCKS経由でインターネットにアクセスし、どのような通信が行われているかを確認してみます。

事前課題で確認したtcpdumpの使い方通りに、tcpdumpを実行してみましょう。
一例として1080番ポートのパケットをキャプチャします。
```shell-session
$ sudo safe_tcpdump ens5 'tcp port 1080'
```

tcpdump起動中に実際に好きなWebサイトにアクセスし、パケットキャプチャを実行します。
必要なキャプチャが済んだら、Ctrl + Cで終了します。

事前課題で確認した手順で、生成されたPCAPファイルを手元にダウンロードし、Wiresharkでどのようなフローで通信が行われていたか（例: Method交渉、Requests、Replies）を一緒に確認してみましょう。

以上が共通課題です。ここまでできましたらCTFdの講義課題2にチャレンジしてください。

**講義課題2: 共通課題で自作したSOCKSが正常に動作したら、コンソール上で表示されているフラグを講義課題2のFlag欄に入力してください。**


## 中級課題（任意）

共通課題が完了し、余裕がある方は次は中級課題に取り組んでいただけますと幸いです。（中級課題を飛ばして、先に上級課題に取り組むのも大歓迎です。）

共通課題では、ブラウザで「SOCKS v5 を使用するときは DNS もプロキシーを使用する」にチェックを入れた場合、宛先のドメイン名（ATYP=0x03）を取得できることが確認できました。中級課題では、SOCKSでドメイン名を取得できることを利用し、簡単なインスペクション機能、すなわちドメイン名に基づくフィルタリング機能を実装してみましょう。

まずは、`src/intermediate.rs`をコピーし、`main.rs`にペーストして上書きします。

3つ簡単な穴埋め課題を用意していますので、取り組んでください。

穴埋め課題1: `main.rs` L6-9
```rust
// 遮断対象のドメイン例。
// 完全一致またはサフィックス一致（サブドメイン含む）で判定します。
// 穴埋め課題1: 配列にブロックしたい好きなドメインを追加してください。
const BLOCKED_SUFFIXES: &[&str] = &["example.com", "bad.example"];
```

穴埋め課題2: `main.rs` L19-40
```rust
fn main() -> io::Result<()> {
    // 1) リスナーを立てる
    // 穴埋め課題2: 共通課題で穴埋めしたときと同じアドレスを指定してください。
    let listener = TcpListener::bind("ここを穴埋め")?;
    println!("SOCKS5 proxy (intermediate) on {}", listener.local_addr()?);

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
```

穴埋め課題3: `main.rs` L132-144
```rust
            // 簡単なインスペクション: 宛先ホスト名で遮断判定し、REP=0x02 を返す
            if is_blocked(&host) {
                println!("blocked by ruleset: {host}:{port}");
                let mut rep = vec![ここを穴埋め]; // 穴埋め課題3: VER, REP=0x02 (Connection not allowed by ruleset), RSV, ATYP=IPv4の配列を作成してください。（例：let mut rep = vec![0x01, 0x01, 0x01, 0x01];）
                rep.extend_from_slice(&[0, 0, 0, 0]); // BND.ADDR
                rep.extend_from_slice(&[0, 0]); // BND.PORT
                client.write_all(&rep)?;
                client.flush()?;
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    format!("blocked host: {host}"),
                ));
            }
```

穴埋めができたら、共通課題と同じ手順で実行してみましょう。tcpdump起動中に実際に好きなWebサイトにアクセスし、パケットキャプチャを実行します。PCAPを同様にダウンロードし、フィルタリングでアクセスがブロックされた際のパケットと、通常のアクセスのパケットを比較し、どのような違いがあるかWiresharkで一緒に確認してみましょう。

以上が中級課題です。ここまでできましたらCTFdの講義課題3にチャレンジしてください。

**講義課題3: 中級課題で自作したSOCKSが正常に動作したら、コンソール上で表示されているフラグを講義課題3のFlag欄に入力してください。**

## 上級課題（任意）

中級課題も完了し、さらに余裕がある方は上級課題に取り組んでいただけますと幸いです。

これまでつくってきたSOCKSは、メソッド交渉で0x00（NO AUTHENTICATION REQUIRED）しか返しませんでした。上級課題では、この認証方式を拡張し、0x00に加えて0x02（USERNAME/PASSWORD認証）を実装してみましょう。

SOCKS5のUSERNAME/PASSWORD認証は、RFC 1929で別途仕様が定められています。

- [IETF Datatracker: Username/Password Authentication for SOCKS V5](https://datatracker.ietf.org/doc/html/rfc1929)

これまで取り組んできたRFC読解＋実装のスキルを活用し、RFC 1929をもとに、フルスクラッチで認証部分を実装してみましょう。

まずは`src/advanced.rs`をすべてコピーし、`main.rs`にペーストして上書きします。

以下の部分を実装してみましょう。
実装箇所: `main.rs` L235-239
```rust
// RFC1929: ユーザ/パスワード認証のサブネゴシエーション
fn perform_userpass_auth_inline(stream: &mut TcpStream) -> io::Result<()> {
    //上級課題: RFC1929を読んでフルスクラッチで実装してみましょう。
    //ChatGPT等の生成AIを用いてコーディングしても構いません。
}
```

Codex等を用いてコーディングしても構いません。

許可するユーザ名・パスワードは`env::var`を用いると環境変数で設定することもできます。以下は実装の一例です。この例では、ユーザ名・パスワードを環境変数で設定可能にしているとともに、`.env`が未設定の場合は`user`、`password`がそれぞれユーザ名・パスワードとして用いられます。


```rust
    //許可するユーザ名
    let expected_user = env::var("PROXY_USERNAME").unwrap_or_else(|_| "user".to_string());
    //許可するパスワード
    let expected_pass = env::var("PROXY_PASSWORD").unwrap_or_else(|_| "password".to_string());

    if username == expected_user && password == expected_pass {
    
    } else {

    }
```

実装できましたら、これまでと同じ手順で実行し、パケットをキャプチャしてみましょう。

> [!NOTE]
>デフォルトのブラウザではユーザ名・パスワード認証が使用できない場合があります。そのためブラウザ拡張機能「FoxyProxy」をインストールしてください。
>
>FoxyProxyの設定画面から、「プロキシー」タブを選択し、「追加」を選択、種類の欄は「SOCKS5」を選択し、ホスト名・ポートはこれまでと同じものを入力してください。ユーザ名・パスワードの欄はご自身が実装されたユーザ名・パスワードをそれぞれ入力してください。
>
><img alt="Image" src="https://github.com/user-attachments/assets/bf940455-11ab-43b6-a209-856e6855a7db" />
>
>ここまでできましたら、FoxyProxyで当該プロキシをONにしてください。
>
><img alt="Image" src="https://github.com/user-attachments/assets/14e00a27-fc4d-4715-a843-fcd1aaa32356" />

パケットキャプチャが完了したら、PCAPを同様にダウンロードし、ユーザ名・パスワード認証がなされた際のパケットを、Wiresharkで一緒に確認してみましょう。

以上が上級課題です。ここまでできましたらCTFdの講義課題4にチャレンジしてください。

**講義課題4: 上級課題で自作したSOCKSが正常に動作したら、コンソール上で表示されているフラグを講義課題4のFlag欄に入力してください。**