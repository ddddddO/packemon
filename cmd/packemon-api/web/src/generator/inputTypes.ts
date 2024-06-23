export type IPv4Inputs = {
  protocol: string
  srcIP: string
  dstIP: string
}

export type EthernetInputs = {
  dstMAC: string
  srcMAC: string
  type: string
}

export type FormInput = {
  ipv4: IPv4Inputs
  ethernet: EthernetInputs
}
