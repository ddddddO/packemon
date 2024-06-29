import Button from 'react-bootstrap/Button'
import Col from 'react-bootstrap/Col'
import Form from 'react-bootstrap/Form'
// ref: https://react-hook-form.com/get-started
import { useForm, SubmitHandler } from 'react-hook-form'
import Ethernet from './Ethernet'
import IPv4 from './IPv4'
import { FormInput } from './inputTypes'
import { getEndpoint } from '../endpoint'

const handleSend = (input: FormInput) => {
  const body = {
    protocol: input.ipv4.protocol,
    src_ip: input.ipv4.srcIP,
    dst_ip: input.ipv4.dstIP,

    dst_mac: input.ethernet.dstMAC,
    src_mac: input.ethernet.srcMAC,
    type: input.ethernet.type,
  }
  const params = {
    method: 'POST',
    headers: {
      'content-type': 'application/json; charset=UTF-8',
    },
    body: JSON.stringify(body),
  }

  fetch(getEndpoint(), params)
    .then((data) => data.json())
    .then((resp) => console.log(resp))
    .catch((error) => console.error(error))
}

export default () => {
  const {
    register,
    handleSubmit,
    watch,
    formState,
  } = useForm<FormInput>()
  const onSubmit: SubmitHandler<FormInput> = (data) => {
    handleSend(data)

    console.log('Send data')
    console.log(data)
  }

  return (
    <Col sm={3}>
      <h2>Generator</h2>
      <Form onSubmit={handleSubmit(onSubmit)}>
        <Ethernet register={register} watch={watch} formState={formState} />
        {(watch('ethernet.type') === '0x0800' || watch('ethernet.type') === undefined)
          && <IPv4 register={register} watch={watch} formState={formState} />
        }
        <Button variant="primary" type="submit">
          Send
        </Button>
      </Form>
    </Col>
  )
}

