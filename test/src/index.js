// local import test: 
import {LiquidCrypto} from '../../LiquidCrypto.js'

const init = async () => {

	// instantiate keypairs
	const liquidCrypto = await LiquidCrypto()
	const liquidCrypto2 = await LiquidCrypto()

	// derive symmetric encryption key
	const secretKey2 = await liquidCrypto2.deriveKey(liquidCrypto.publicKey)

	const secret = 'secret data'

	console.log('secret: ', secret)

	const encodedSecret = await liquidCrypto2.encrypt(secret, secretKey2)

	console.log('encrypted secret: ', encodedSecret)

	const secretKey = await liquidCrypto.deriveKey(liquidCrypto2.publicKey)

	const decodedSecret = await liquidCrypto.decrypt(encodedSecret, secretKey)

	console.log('decodedSecret: ', decodedSecret)
}

init()