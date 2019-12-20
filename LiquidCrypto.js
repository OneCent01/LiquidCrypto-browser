const ab2str = buf => String.fromCharCode.apply(null, new Uint8Array(buf))

const str2ab =  str => {
  const buf = new ArrayBuffer(str.length),
    bufView = new Uint8Array(buf)
  let i = str.length
  while(i--) {
    bufView[i] = str.charCodeAt(i)
  }
  return buf
}

const LiquidCrypto = async (keypair) => {
	const generateKeys = () => crypto.subtle.generateKey(
	    {
	        name: "ECDH",
	        namedCurve: "P-256", 
	    },
	    true, 
	    ["deriveKey"] 
	)

	const liquidState = {
		keypair: keypair || await generateKeys()
	}

	const deriveKey = (publicKey) => crypto.subtle.deriveKey(
	    {
	        name: "ECDH",
	        namedCurve: "P-256",
	        public: publicKey, 
	    },
	    liquidState.keypair.privateKey,
	    { 
	        name: "AES-GCM", 
	        length: 256, 
	    },
	    false, 
	    ["encrypt", "decrypt"] 
	)

	const encrypt = async (data, key) => {
		const iv = crypto.getRandomValues(new Uint8Array(12))
		const dataBuffer = new TextEncoder().encode(data).buffer
		const encrypted = await crypto.subtle.encrypt(
			{
				name: 'AES-GCM',
				iv
			},
			key,
			dataBuffer
		)
		return `${ab2str(iv)}${ab2str(encrypted)}`
	}

	const decrypt = async (data, key) => {
		const iv = data.slice(0, 12)
		const encData = data.slice(12)
		return new TextDecoder().decode(await crypto.subtle.decrypt(
			{
				name: "AES-GCM",
				iv: str2ab(iv)
			},
			key,
			str2ab(encData)
		))
	}

	return {
		publicKey: liquidState.keypair.publicKey,
		deriveKey,
		encrypt,
		decrypt
	}
}

module.exports = { LiquidCrypto }
