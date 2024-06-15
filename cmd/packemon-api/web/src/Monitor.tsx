import { useState, useRef, useEffect } from 'react'

const ENDPOINT: string = (() => {
  let loc = window.location;
  let uri = 'ws:';
  if (loc.protocol === 'https:') {
      uri = 'wss:';
  }
  uri += '//' + loc.host;
  uri += loc.pathname + 'ws';
  return uri
})()

// const ENDPOINT_DEV: string = "ws://localhost:8082/ws"

// ref: https://qiita.com/_ytori/items/a92d69760e8e8a2047ac#3hello-world---react-x-websocket-%E3%81%AE%E5%9F%BA%E6%9C%AC%E5%BD%A2
export default () => {
  const [packets, setPackets] = useState<string[]>([''])
  const socketRef = useRef<WebSocket>()

  // #0.WebSocket関連の処理は副作用なので、useEffect内で実装
  useEffect(() => {
    // #1.WebSocketオブジェクトを生成しサーバとの接続を開始
    // const websocket = new WebSocket(ENDPOINT_DEV)
    const websocket = new WebSocket(ENDPOINT)
    socketRef.current = websocket

    // #2.メッセージ受信時のイベントハンドラを設定
    const onMessage = (event: MessageEvent<string>) => {
      setPackets((prev) => [event.data, ...prev])
    }
    websocket.addEventListener('message', onMessage)

    // #3.useEffectのクリーンアップの中で、WebSocketのクローズ処理を実行
    return () => {
      websocket.close()
      websocket.removeEventListener('message', onMessage)
    }
  }, [])

  return (
    <>
      <p>{`New!: ${packets[0]} / ${packets.length-2}`}</p>
      <div>
        {packets.map((p) => <p>{p}</p>)}
      </div>
    </>
  )
}