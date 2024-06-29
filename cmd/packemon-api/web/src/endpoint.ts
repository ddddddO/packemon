export const getEndpoint = (): string => {
  const loc = window.location
  return loc.hostname === 'localhost'
        ? 'http://localhost:8082/packet'
        : loc.protocol + '//' + loc.host + '/packet'
}

export const getEndpointWS = (): string => {
  const endpoint: string = (() => {
    const loc = window.location
    const protocol = loc.protocol === 'https:' ? 'wss:' : 'ws:'
    return protocol + '//' + loc.host + loc.pathname + 'ws'
  })()
  
  const endpointDev: string = "ws://localhost:8082/ws"
  return window.location.hostname === 'localhost' ? endpointDev : endpoint
}