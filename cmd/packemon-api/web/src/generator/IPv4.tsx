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
  const protocols: Option[] = [{value: "0x01", label: "ICMP"}, {value: "0x06", label: "TCP"}, {value: "0x11", label: "UDP"}]
  const ipAddressValidation = { required: true, minLength: 7, maxLength: 15 }

  console.log(watch('ipv4.protocol'))

  return (
    <>
      <h3>IPv4</h3>
      <Form.Group className="mb-3" controlId="formProtocols">
        <InputGroup.Text>Protocol</InputGroup.Text>
        <Form.Select 
          aria-label="Default select example"
          {...register('ipv4.protocol')}
        >
          {protocols.map((p) => <option value={p.value}>{p.label}</option>)}
        </Form.Select>
      </Form.Group>
      <Form.Group className="mb-3" controlId="formSrcIP">
        <InputGroup.Text>Source IP Address</InputGroup.Text>
        <Form.Control
          placeholder="e.g.) 192.168.10.110"
          {...register('ipv4.srcIP', ipAddressValidation)}
          aria-invalid={errors.ipv4?.srcIP ? "true" : "false"}
        />
        {errors.ipv4?.srcIP?.type === 'required' && <span>This field is required</span>}
        {errors.ipv4?.srcIP?.type === 'minLength' && <span>This field is required 7 chars</span>}
        {errors.ipv4?.srcIP?.type === 'maxLength' && <span>This field is max 15 chars</span>}
      </Form.Group>

      <Form.Group className="mb-3" controlId="formDstIP">
        <InputGroup.Text>Destination IP Address</InputGroup.Text>
        <Form.Control
          placeholder="e.g.) 192.168.10.110"
          {...register('ipv4.dstIP', ipAddressValidation)}
          aria-invalid={errors.ipv4?.dstIP ? "true" : "false"}
        />
        {errors.ipv4?.dstIP?.type === 'required' && <span>This field is required</span>}
        {errors.ipv4?.dstIP?.type === 'minLength' && <span>This field is required 7 chars</span>}
        {errors.ipv4?.dstIP?.type === 'maxLength' && <span>This field is max 15 chars</span>}
      </Form.Group>
    </>
  )
}