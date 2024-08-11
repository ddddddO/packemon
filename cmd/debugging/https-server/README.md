- 準備は、`tls-server` の README 参照
- client は、 `sudo go run cmd/packemon/main.go --send --debug --proto https-get` で HTTP GET を TLSv1.2 でリクエストできる

## その様子

|-|暗号化|復号|備考|
|--|--|--|--|
|全体フロー|![](../../../assets/encrypted_http.png)|![](../../../assets/decrypted_http.png)||
|HTTPリクエスト（GET）|![](../../../assets/encrypted_http_request.png)|![](../../../assets/decrypted_http_request.png)||
|HTTPレスポンス|![](../../../assets/encrypted_http_response.png)|![](../../../assets/decrypted_http_response.png)||
