/*  test connection */

//const { Core } = require('@adobe/aio-sdk')
const openpgp = require('@tripod/openpgp'); 
const Utils = require('../utils');

async function main (params) {
  const util = new Utils(params);
  
  try {
	const {privateKeyArmored, publicKeyArmored, secret} = util.getPGPKeys(); 
	
	if (params.checkDecryption && (!privateKeyArmored || !publicKeyArmored || !secret)) {
		return {
			'Content-Type': 'application/json',
			statusCode: 400,
			body: {
				error: 'Missing one or more required configurations for encryption.'
			}
		}		
	}
	
	const { keys: [privateKey] } = await openpgp.key.readArmored(privateKeyArmored);
	await privateKey.decrypt(secret);
	
	if (params.checkDecryption) {
		const data = util.getPayloadData();		
		
		if (!data) {
			return {
				'Content-Type': 'application/json',
				statusCode: 400,
				body: {
					error: 'Missing encrypted payload data.'
				}
			}		
		}		

		const { data: decrypted, signatures: checkSig } = await openpgp.decrypt({
			message: await openpgp.message.readArmored(data),            			// parse armored message
			publicKeys: (await openpgp.key.readArmored(publicKeyArmored)).keys,	// check message signing
			privateKeys: [privateKey]                                       		// for decryption
		});
	
		if (checkSig[0].valid) {	
			
			return {
			  statusCode: 200,
			  body: JSON.parse(decrypted)
			}
		}
		else {
			return {
			  statusCode: 500,
			  body: {response: "Invalid Singnature"}
			}
		}
	}
	else if (params.checkEncryption) {
		const returnMsg = {message: "This is a test message from Adobe @ " + new Date()};

		openpgp.config.compression = openpgp.enums.compression.zip;
		openpgp.config.prefer_hash_algorithm = openpgp.enums.hash.sha256;		
		openpgp.config.encryption_cipher = openpgp.enums.symmetric.aes256;
		openpgp.config.show_comment = false;
		
		const { data: encrypted} = await openpgp.encrypt({
			message: await openpgp.message.fromText(JSON.stringify(returnMsg)),     // parse decrypted message
			publicKeys: (await openpgp.key.readArmored(publicKeyArmored)).keys,	// for encrypting the message
			privateKeys: [privateKey],                                       	// for signing the message
			armor: true,
			detached: false
		});			
		
		return {
		  'Content-Type': 'text/plain',
		  statusCode: 200,
		  body: encrypted
		}	
	}
	else {
		return {
		  statusCode: 200,
		  body: {response: 'Test Connection successful.'}
		}		
	}
  } catch (error) {
    return {
      statusCode: 500,
      body: { error: error.toString() }
    }
  }
}

exports.main = main
