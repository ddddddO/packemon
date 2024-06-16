import { useState, useRef, useEffect } from 'react'
import Table from 'react-bootstrap/Table'

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

type Props = {
  onChange: (arg0: number) => void
}

// ref: https://qiita.com/_ytori/items/a92d69760e8e8a2047ac#3hello-world---react-x-websocket-%E3%81%AE%E5%9F%BA%E6%9C%AC%E5%BD%A2
export default ({ onChange }: Props) => {
  const [packets, setPackets] = useState<string[]>([])
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
      onChange(packets.length)
    }
    websocket.addEventListener('message', onMessage)

    // #3.useEffectのクリーンアップの中で、WebSocketのクローズ処理を実行
    return () => {
      websocket.close()
      websocket.removeEventListener('message', onMessage)
    }
  }, [])

  const count = packets.length

  return (
    <>
      <p>{`New!: ${packets[0]} / ${count}`}</p>

      <Table striped bordered variant="dark">
        <thead>
          <tr>
            <th>#</th>
            <th>Destination MAC</th>
            <th>Source MAC</th>
            <th>Type</th>
            <th>Proto</th>
            <th>Destination IP</th>
            <th>Source IP</th>
          </tr>
        </thead>
        <tbody>
          {packets.map((p, index) => {
            return (
              <tr>
                <td>{count-index}</td>
                <td>x</td>
                <td>x</td>
                <td>x</td>
                <td>{p}</td>
                <td>x</td>
                <td>x</td>
              </tr>
            )
          })}
        </tbody>
      </Table>
    </>
  )
}