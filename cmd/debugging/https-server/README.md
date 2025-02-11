- 準備は、`tls-server` の README 参照
- client は、 `sudo go run cmd/packemon/main.go --send --debug --proto https-get` で HTTP GET を TLSv1.2 でリクエストできる（[そのメソッド](../../../internal/debugging/send_https_get_after_tcp3way_tlshandshake.go)）

- curl で tlsv1.2 でリクエストは、`curl --tls-max 1.2 -k https://192.168.10.112`

## その様子

|-|暗号化|復号|備考|
|--|--|--|--|
|全体フロー|![](../../../assets/encrypted_http.png)|![](../../../assets/decrypted_http.png)||
|HTTPリクエスト（GET）|![](../../../assets/encrypted_http_request.png)|![](../../../assets/decrypted_http_request.png)||
|HTTPレスポンス|![](../../../assets/encrypted_http_response.png)|![](../../../assets/decrypted_http_response.png)||

