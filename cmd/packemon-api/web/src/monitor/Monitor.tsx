import { useState, useRef, useEffect } from 'react'
import Col from 'react-bootstrap/Col'
import Table from 'react-bootstrap/Table'
import Pagination from 'react-bootstrap/Pagination'
import _ from 'lodash'

const ENDPOINT: string = (() => {
  const loc = window.location
  const protocol = loc.protocol === 'https:' ? 'wss:' : 'ws:'
  return protocol + '//' + loc.host + loc.pathname + 'ws'
})()

const ENDPOINT_DEV: string = "ws://localhost:8082/ws"

type Packet = {
  dstMAC: string
  srcMAC: string
  type: string
  proto: string
  dstIP: string
  srcIP: string
}

// ref: https://qiita.com/_ytori/items/a92d69760e8e8a2047ac#3hello-world---react-x-websocket-%E3%81%AE%E5%9F%BA%E6%9C%AC%E5%BD%A2
export default () => {
  const [packets, setPackets] = useState<Packet[]>([])
  const socketRef = useRef<WebSocket>()
  const endpoint = !window.location.host.match(/8082/) ? ENDPOINT_DEV : ENDPOINT
  const [pageNum, setPageNum] = useState(1)
  const handlePagination = (e: any) => {
    setPageNum(e.target.text)
  }

  // #0.WebSocket関連の処理は副作用なので、useEffect内で実装
  useEffect(() => {
    // #1.WebSocketオブジェクトを生成しサーバとの接続を開始
    const websocket = new WebSocket(endpoint)
    socketRef.current = websocket

    // #2.メッセージ受信時のイベントハンドラを設定
    const onMessage = (event: MessageEvent<string>) => {
      const parsed = JSON.parse(event.data)
      const packet: Packet = {
        dstMAC: parsed.dst_mac,
        srcMAC: parsed.src_mac,
        type: parsed.type,
        proto: parsed.proto,
        dstIP: parsed.dst_ip,
        srcIP: parsed.src_ip,
      }

      setPackets((prev) => [packet, ...prev])
    }
    websocket.addEventListener('message', onMessage)

    // #3.useEffectのクリーンアップの中で、WebSocketのクローズ処理を実行
    return () => {
      websocket.close()
      websocket.removeEventListener('message', onMessage)
    }
  }, [])

  const count = packets.length
  const range = 10

  return (
    <Col sm={8}>
      <h2>Monitor</h2>
      {/* <p>{`New!: ${packets[0] ? packets[0].proto: "-"} / ${count}`}</p> */}

      <Pagination size='sm'>
        {_.range(packets.length / range).map((v: number) => {
          const page = v + 1
          return <Pagination.Item key={page} active={page === pageNum} onClick={handlePagination}>{page}</Pagination.Item>
        })}
      </Pagination>

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
          {_.slice(packets, (pageNum-1)*range, pageNum*range).map((p: Packet, i: number) => {
            return (
              <tr>
                <td>{count - ((pageNum-1)*range + i)}</td>
                <td>{p.dstMAC}</td>
                <td>{p.srcMAC}</td>
                <td>{p.type}</td>
                <td>{p.proto}</td>
                <td>{p.dstIP}</td>
                <td>{p.srcIP}</td>
              </tr>
            )
          })}
        </tbody>
      </Table>
    </Col>
  )
}