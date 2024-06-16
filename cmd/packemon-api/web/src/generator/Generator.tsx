import Button from 'react-bootstrap/Button'
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

const Ethernet = () => {
  const etherTypes: Option[] = [{value: "0x0800", label: "IPv4"}, {value: "0x0806", label: "ARP"}]
  const {
    register,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<EthernetInputs>()
  const onSubmit: SubmitHandler<EthernetInputs> = (data) => console.log(data)

  const macAddressValidation = { required: true, minLength: 14, maxLength: 14 }

  console.log(watch('srcMAC'))

  return (
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
  )
}

export default () => {
  return (
    <>
      <h3>Ethernet</h3>
      <Ethernet />
    </>
  )
}

