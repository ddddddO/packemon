import Button from 'react-bootstrap/Button'
import Col from 'react-bootstrap/Col'
import Form from 'react-bootstrap/Form'
// ref: https://react-hook-form.com/get-started
import { useForm, SubmitHandler } from 'react-hook-form'
import Ethernet from './Ethernet'
import { FormInput } from './inputTypes'

const handleSend = (endpoint: string, input: FormInput) => {
  const body = {
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

  fetch(endpoint, params)
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

  const loc = window.location
  const endpoint = !window.location.host.match(/8082/) ? 'http://localhost:8082/packet' : loc.protocol + '//' + loc.host + '/packet'
  const onSubmit: SubmitHandler<FormInput> = (data) => {
    handleSend(endpoint, data)

    console.log('Send data')
    console.log(data)
  }

  return (
    <Col sm={3}>
      <h2>Generator</h2>
      <Form onSubmit={handleSubmit(onSubmit)}>
        <Ethernet register={register} watch={watch} formState={formState} />
        <Button variant="primary" type="submit">
          Send
        </Button>
      </Form>
    </Col>
  )
}

