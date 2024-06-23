export type EthernetInputs = {
  dstMAC: string
  srcMAC: string
  type: string
}

export type FormInput = {
  ethernet: EthernetInputs
}
