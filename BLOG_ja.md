[OPENLOGI Advent Calendar 2024](https://qiita.com/advent-calendar/2024/openlogi) 4日目の記事です。
https://qiita.com/advent-calendar/2024/openlogi

3日目の記事は、[riku929hr](https://zenn.dev/riku929hr) さんの「**[育休を取得するときのあれこれ](https://zenn.dev/openlogi/articles/all-about-parental-leave)**」でした！

# はじめに
この記事では主に、ここ１年近くを通した、ネットワークについて自身が何をしてきたかを書こうと思います。

みなさんは、ネットワークに関わる何らかツールを作りたい、と思ったことはありませんか？
私が想像するネットワークなツールでパッと思いつくのは cURL コマンドです。Web系企業に勤められている方は、Postman も馴染み深いでしょうか。検証/調査に関わる方は、Wireshark を利用されていたりするでしょうか。

私は、ネットワークについてなんとなくはわかっているつもりだけど、具体的にはよくわかってない、と感じていました。
また、ツールを作ることが好きなのですが、大体がローカルのホスト内で完結するツールでした。
だからかわかりませんが、「なにかネットワークに関わるツールを作りたいな...」と、かなり前から思っていました（3年位前から?）。

# なにをしたか
たしか、業務中の障害調査がきっかけで、ネットワークについてもっと知りたい、という想いが強くなり、とりあえずネスぺの勉強を始めました（体系的に学ぶなら IPA のネスペだろうと思い）。学習スタイルは人により様々あると思いますが、私は参考書を読んで過去試験を解く、みたいな感じで進めていました。ただ私の場合、モチベーションが保てなくなり、捗らなくなっていきました（試験自体は、午前1を受けて帰りました😇ネスペに合格された方を本当に尊敬しています）。

そんな中、たまたま寄った本屋に平積みされた「**[体験しながら学ぶ ネットワーク技術入門](https://www.sbcr.jp/product/4815618599/)**」が目に留まり、「タイムリーに面白そうな本が出てる！」と思いすぐに購入しました。
https://www.sbcr.jp/product/4815618599/
こちらの本はとてもお勧めで、Docker 環境でサクッとネットワーク環境を構築して検証でき、解説もわかりやすく優れた書籍だと思います（この本を読みつつ検証をしている時の[作業スレ](https://x.com/ddddddOpppppp/status/1764218935581593602)）

実際に手を動かしてみて楽しいと感じ、より実践的な内容でネスペより難易度が優しそうでかつ体系的な知識習得が CCNA でできそうと思い、ネスぺから CCNA に学習を切り替え、無事試験を pass しました（[証明書](https://github.com/ddddddO/profile/blob/main/doc/Cisco%20Certified%20Network%20Associate%20certificate.pdf)。嬉しかったです）。
試験自体は、少し日本語翻訳が怪しかったところはありますが、コンフィグの設定をして、ホスト間で ping が通るようにするとか、ルーティングの設定をするとか出てきて楽しかったです。非常に焦りましたが。
（ちなみに、CCNA の参考書は、「**[シスコ技術者認定教科書 CCNA 完全合格テキスト＆問題集［対応試験］200-301](https://www.shoeisha.co.jp/book/detail/9784798165776)**」を利用しました。白本と呼ばれているようで、800ページを超すボリュームで一読するのも大変でした）
https://www.shoeisha.co.jp/book/detail/9784798165776

ここまでで、かなりネットワークの解像度は上がったと思います。なのでいよいよツール作成です！...といきたいのですが、肝心の「どんなツールを作ればいいかわからない」問題がありました。
（最近、同様の問題を取り上げた記事が出ていましたね。「**[個人開発をしてみたいけど、作りたいものがない人へ](https://note.com/choo/n/n3fa91438b882)**」。こちらの記事中にある、**「とりあえず作ってみる」** のところはとても共感しました）
https://note.com/choo/n/n3fa91438b882

作成するツールの手がかり何かないかなと探っていたのですが、「**[Golangで作るソフトウェアルータ(物理本)](https://booth.pm/ja/items/5290391)**」 という書籍[^1]がありました。
https://booth.pm/ja/items/5290391
こちらはタイトル通りの内容で、一通り読んでみて、「Wireshark みたいにパケット見られるもの作ってみたい、あと、自由にパケット作れるツールにもしたい」と思い立ちました（後述するツール実装の参考にもなり、大変助かりました🙏）
また、今まで TUI ツールを作ったことがなく、どんな感じか試してみたかったため、上記機能と合わせて、**「TUI ベースのパケット生成・モニターツール」** を作ってみよう、と考えました。

そうして爆誕したのが、**Packemon**（パケモン）です。
https://github.com/ddddddO/packemon

名前の由来は、パケットのモンスターとか、パケットキャプチャツールのパチモンとか、TCP/IPモデルの各層でカプセル化・非カプセル化するイメージだったりです（全く異なる機能ですが、既存で同名のツールはあるんですけどね。[milesj/packemon](https://github.com/milesj/packemon)）
ちなみに、↑の OGP で表示されている顔文字は社内の Slack でやり取りされていたものを拝借しカプセル的なモノに差し替えました。このツールのイメージにピッタリと思います。

(っ‘-’)╮=͟͟͞͞◒ ヽ( '-'ヽ) 

# Packemon とは
詳しくは README を参照いただきたいのですが、一言でいうと **「パケットを生成・モニターするためのTUIツール」** です（下の GIF では、DNSクエリを投げてそのレスポンスの詳細表示をする操作をしています。[操作方法](https://github.com/ddddddO/packemon?tab=readme-ov-file#sending-dns-query-and-monitoring-dns-response)）。

![](https://storage.googleapis.com/zenn-user-upload/39d9343ff71a-20250116.gif)

具体的には、Linux の場合は [raw socket](https://github.com/ddddddO/packemon/blob/3e1e9d7bc60ee93c0f15e17e3756740f01a501f3/networkinterface_linux.go#L43-L58) を使用し、
- TCP/IPモデルの各層をユーザーの任意の入力でパケットを生成して送信（イメージの左）
- 送受信したパケットをTCP/IPモデルの各層でパースしてそれを画面に表示（イメージの右）

ができるというものです。ただ、対応しているプロトコルは現状少なく、各プロトコル実装もまだまだなレベルが多いです（Ethernet/ARP/IPv4/IPv6/ICMP/TCP/UDP/TLSv1.2/DNS/HTTP）。

:::message
2025/05/24 macOS/Windows にも対応しました🎉
[gopacket/gopacket](https://github.com/gopacket/gopacket)を利用しています。[この辺り](https://github.com/ddddddO/packemon/blob/3e1e9d7bc60ee93c0f15e17e3756740f01a501f3/networkinterface_darwin.go#L91-L119)
:::

そして、まだまだなレベルではあるのですが、今度はルーティングプロトコルに挑戦していて、まずは、BGP で利用されるパケットを作ってみて、対向のBGPルータ（Dockerコンテナ）とやり取りできるか？ということをしています（[作業記録](https://github.com/ddddddO/packemon/blob/main/cmd/debugging/bgp/README.md)。以下は、自作 BGP パケット（src ip: `172.17.0.4`）で一連のやり取りができた時の Wireshark の様子。実際に経路情報を入れて更新する場合、結構プログラムに手を加えないとダメそう）

![](https://storage.googleapis.com/zenn-user-upload/3561632176bb-20241126.png)

追記（2024/12/29）
積んでいた「**[ピアリング戦記 ― 日本のインターネットを繋ぐ技術者たち](https://www.lambdanote.com/products/peering)**」を読みました。
https://www.lambdanote.com/products/peering

BGP という技術はありますが、それを使って相互接続するには、組織の力関係（トラフィック量）や IX にどれだけの・どんな AS が繋がっているかとか、人との関わりなど、だいぶ人間の活動があってこそなのだなと思いました。
BGP についての技術的な概説や、インターネットとは何か・BGP を軸とした日本のインターネットの変遷というのが知れる書籍で、とても面白かったです。
BGP や AS、IX など、インターネットを支える重要なことを具体的にイメージして知れる良い本だと思いました。

# Packemon を作っていく中で

このツールを作っている途中、大きな壁にぶつかりました。

TCP の 3way handshake も自作したいと思い実装を進めていたのですが、どうも handshake がうまくいかず、Wireshark を見ると、TCP の RST パケットがこちらから送られていることがわかりました。え、プログラム上そんなことしてないけど... 調べると、どうやらカーネルが RST パケットを自動で送信しているということがわかりました。そこから、さらに調べてみて実装を変えてみたりしたのですが、どうもダメ。

もう諦めて、handshake の処理は Go の標準パッケージに委ねようかと思い、一度そうしました。
しかし諦めがつかず、どうにかできないか調べ続けました。
（逸れますが、標準パッケージ内にヒントがないか探っていた時に発見した Gopher くんです）

https://x.com/ddddddOpppppp/status/1786648428661109231

調査していく中で、eBPF なるものが使えるかも？と思い、「**[入門 eBPF―Linuxカーネルの可視化と機能拡張](https://www.oreilly.co.jp/books/9784814400560/)**」 を読んでみました。
https://www.oreilly.co.jp/books/9784814400560/
eBPF は、カーネルのソースコード自体を変えることなくカーネルに作用するプログラムを差し込め、必要であればユーザ空間とカーネル空間でデータのやり取りができる技術（と捉えています）で、Go でもそれ用の[ライブラリ](https://github.com/cilium/ebpf)はあったため、実際に試してみて、ようやく TCP の 3way handshake ができるようになりました（[送信される RST パケットをドロップする処理](https://github.com/ddddddO/packemon/blob/6fc096c071d59557d7b6f080feb512e74e731fd0/egress_control/egress_packet.bpf.c#L159-L168)を組み込みました）。
eBPF ですが、かなり強力な武器を手に入れた気持ちです（eBPF の大筋の理解は「[eBPFのこれまでとこれから](https://speakerdeck.com/yutarohayakawa/ebpfnokoremadetokorekara)」がわかりやすいです）。

また、ツール作成と並行して、「**[ポートスキャナ自作ではじめるペネトレーションテスト―Linux環境で学ぶ攻撃者の思考](https://www.oreilly.co.jp/books/9784814400423/)**」を読んでいました。
https://www.oreilly.co.jp/books/9784814400423/
こちらの本を読んでいて、「Packemon、 DoS とか攻撃用のツールにもなりそう」と思い、同一LAN内の別PC（私物のRaspberry Pi）にレスポンスが返るように、このツールで DNS クエリのパケットを生成してみると成功しました（ref: [DNSリフレクション攻撃](https://eset-info.canon-its.jp/malware_info/qa/detail/150626_1.html)）。おおっ、となりました。
また、少し実装を追加すれば [ARPスプーフィング](https://www.scskserviceware.co.jp/topics/primedesk/665.html) も可能そうです。

ちなみに、こちらの本では、どのような流れで攻撃者が攻撃を準備し実行して目的を達成するかの解説や、ペネトレーションのためのツール紹介などがあり、知らない世界だったため大変面白く読めました。特に、世に[攻撃テスト用のツール](https://github.com/rapid7/metasploit-framework)が GitHub で公開されているんだなと驚きましたし、戦争で敵側のメールで偽の集合場所を伝えられた兵士たちが攻撃された、といった現実世界で IT がそういう道具として使われていることが心にきました。

# さいごに

基本的な知識を得た上で、実際に手を動かしてパケットがどうなっているかキャプチャツールで確認したり、ネットワークなツール開発をしたりするのは、ネットワークを学ぶのにとても良いんじゃないかなと思いました。体感しているわけですからきっと記憶の定着にも良いでしょうし、何より楽しいかなと思います（ネットワークを本業にしている方には到底及ばないとは思いますが...）。

ちなみに、
https://blog.ichikaway.com/entry/20240801/ore-no-tls
「**[迂闊にTLS/SSLをPHPで実装してみたら最高だった件](https://blog.ichikaway.com/entry/20240801/ore-no-tls)**」にある、

> 試行錯誤しながら色々と調べてトライしている時は、まるでパズルを解いているような感覚

と似た感じを持ちました。
作りたいプロトコルのパケットを流して Wireshark で観察 → 実装 → Wireshark で観察... のサイクルを繰り返し、最後実装したプロトコルのパケットでちゃんとレスポンスが返ってきたときはとても興奮します！エキサイティング！

また、特定プロトコルでのチェックサム計算処理や、TLS の実装などなど、先に取り上げた「[Golangで作るソフトウェアルータ(物理本)](https://booth.pm/ja/items/5290391)」の著者 **[satoken](https://zenn.dev/satoken)さん**の Zenn の記事やコードに非常に助けられました。ありがとうございます！！

そして、こういったネットワークなツール開発には Wireshark は欠かせないと実感しました（おそらく永遠に開発が終わらないツールを見つけられたと思います。良いか悪いかわかりませんが...笑）

最後に、本記事を書いた後でこんな動画を見つけました。少し関係しそうだったのでリンクします。過激なタイトルですが、内容は面白かったです。
https://www.youtube.com/watch?v=syB9PjUr0WE

[OPENLOGI Advent Calendar 2024](https://qiita.com/advent-calendar/2024/openlogi) 5日目は、[HrsUed](https://qiita.com/HrsUed) さんの「[**苦節14年目で積ん読から解放された話**](https://qiita.com/HrsUed/items/17ef69caed6545c61748)」です！

# 採用

よければぜひ！SRE / CRE / QA　絶賛募集中です！（2024/12/04 現在）
https://herp.careers/v1/openlogi/requisition-groups/486b8b01-6cf9-4434-8601-381c9c092e0d


[^1]: こちら著者は satoken さんで、Zenn にも数々のネットワークプロトコルを自作してみた記事を書かれていて、ツール作成時大変助けられました！（この場を借りて感謝申し上げます）

[^2]: 「**[入門 eBPF―Linuxカーネルの可視化と機能拡張](https://www.oreilly.co.jp/books/9784814400560/)**」参考