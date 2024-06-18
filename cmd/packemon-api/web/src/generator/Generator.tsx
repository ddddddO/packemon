import Button from 'react-bootstrap/Button'
import Col from 'react-bootstrap/Col'
import Form from 'react-bootstrap/Form'
import InputGroup from 'react-bootstrap/InputGroup'
// ref: https://react-hook-form.com/get-started
import { useForm, SubmitHandler } from 'react-hook-form'

type Option = {
  value: string
  label: string
}

type EthernetInputs = {
  dstMAC: string
  srcMAC: string
  type: string
}

const handleSend = (endpoint: string, input: EthernetInputs) => {
  const body = {
    dst_mac: input.dstMAC,
    src_mac: input.srcMAC,
    type: input.type,
  }
  const params = {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=UTF-8',
    },
    body: JSON.stringify(body),
  }

  fetch(endpoint, params)
    .then((data) => data.json())
    .then((resp) => console.log(resp))
    .catch((error) => console.error(error))
}

const Ethernet = () => {
  const etherTypes: Option[] = [{value: "0x0800", label: "IPv4"}, {value: "0x0806", label: "ARP"}]
  const {
    register,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<EthernetInputs>()

  const loc = window.location
  const endpoint = loc.protocol + '//' + loc.host + '/packet'
  const onSubmit: SubmitHandler<EthernetInputs> = (data) => {
    handleSend(endpoint, data)

    console.log('Send data')
    console.log(data)
  }

  const macAddressValidation = { required: true, minLength: 14, maxLength: 14 }

  console.log(watch('srcMAC'))

  return (
    <>
      <h3>Ethernet</h3>
      <Form onSubmit={handleSubmit(onSubmit)}>
        <Form.Group className="mb-3" controlId="formDstMAC">
          <InputGroup.Text>Destination MAC Address</InputGroup.Text>
          <Form.Control
            placeholder="e.g.) 0x00155de44d64"
            {...register('dstMAC', macAddressValidation)}
            aria-invalid={errors.dstMAC ? "true" : "false"}
          />
          {errors.dstMAC?.type === 'required' && <span>This field is required</span>}
          {errors.dstMAC?.type === 'minLength' && <span>This field is required 14 chars</span>}
          {errors.dstMAC?.type === 'maxLength' && <span>This field is max 14 chars</span>}
        </Form.Group>

        <Form.Group className="mb-3" controlId="formSrcMAC">
          <InputGroup.Text>Source MAC Address</InputGroup.Text>
          <Form.Control
            placeholder="e.g.) 0x00155db4ff71"
            {...register('srcMAC', macAddressValidation)}
            aria-invalid={errors.srcMAC ? "true" : "false"}
          />
          {errors.srcMAC?.type === 'required' && <span>This field is required</span>}
          {errors.srcMAC?.type === 'minLength' && <span>This field is required 14 chars</span>}
          {errors.srcMAC?.type === 'maxLength' && <span>This field is max 14 chars</span>}
        </Form.Group>

        <Form.Group className="mb-3" controlId="formEtherType">
          <InputGroup.Text>Ether Type</InputGroup.Text>
          <Form.Select 
            aria-label="Default select example"
            {...register('type')}
          >
            {etherTypes.map((e) => <option value={e.value}>{e.label}</option>)}
          </Form.Select>
        </Form.Group>

        <Button variant="primary" type="submit">
          Send
        </Button>
      </Form>
    </>
  )
}

export default () => {
  return (
    <Col sm={3}>
      <h2>Generator</h2>
      <Ethernet />
    </Col>
  )
}

