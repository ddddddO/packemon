import Generator from './generator/Generator'
import Monitor from './monitor/Monitor'
import './App.css'
import 'bootstrap/dist/css/bootstrap.min.css'
import {
  Container,
  Row,
} from 'react-bootstrap'

function App() {
  return (
    <Container>
      <Row>
        <Generator />
        <Monitor />
      </Row>
    </Container>
  )
}

export default App
