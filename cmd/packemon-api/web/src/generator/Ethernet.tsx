import { UseFormRegister, UseFormWatch, FormState } from 'react-hook-form'
import Form from 'react-bootstrap/Form'
import InputGroup from 'react-bootstrap/InputGroup'
import { FormInput } from './inputTypes'

type Option = {
  value: string
  label: string
}

type Props = {
  register: UseFormRegister<FormInput>
  watch: UseFormWatch<FormInput>
  formState: FormState<FormInput>  
}

export default ({ register, watch, formState: { errors } }: Props) => {
  const etherTypes: Option[] = [{value: "0x0800", label: "IPv4"}, {value: "0x0806", label: "ARP"}]
  const macAddressValidation = { required: true, minLength: 14, maxLength: 14 }

  console.log(watch('ethernet.srcMAC'))

  return (
    <>
      <h3>Ethernet</h3>
      <Form.Group className="mb-3" controlId="formDstMAC">
        <InputGroup.Text>Destination MAC Address</InputGroup.Text>
        <Form.Control
          placeholder="e.g.) 0x00155de44d64"
          {...register('ethernet.dstMAC', macAddressValidation)}
          aria-invalid={errors.ethernet?.dstMAC ? "true" : "false"}
        />
        {errors.ethernet?.dstMAC?.type === 'required' && <span>This field is required</span>}
        {errors.ethernet?.dstMAC?.type === 'minLength' && <span>This field is required 14 chars</span>}
        {errors.ethernet?.dstMAC?.type === 'maxLength' && <span>This field is max 14 chars</span>}
      </Form.Group>

      <Form.Group className="mb-3" controlId="formSrcMAC">
        <InputGroup.Text>Source MAC Address</InputGroup.Text>
        <Form.Control
          placeholder="e.g.) 0x00155db4ff71"
          {...register('ethernet.srcMAC', macAddressValidation)}
          aria-invalid={errors.ethernet?.srcMAC ? "true" : "false"}
        />
        {errors.ethernet?.srcMAC?.type === 'required' && <span>This field is required</span>}
        {errors.ethernet?.srcMAC?.type === 'minLength' && <span>This field is required 14 chars</span>}
        {errors.ethernet?.srcMAC?.type === 'maxLength' && <span>This field is max 14 chars</span>}
      </Form.Group>

      <Form.Group className="mb-3" controlId="formEtherType">
        <InputGroup.Text>Ether Type</InputGroup.Text>
        <Form.Select 
          aria-label="Default select example"
          {...register('ethernet.type')}
        >
          {etherTypes.map((e) => <option value={e.value}>{e.label}</option>)}
        </Form.Select>
      </Form.Group>
    </>
  )
}