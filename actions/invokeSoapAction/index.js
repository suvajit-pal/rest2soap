/*
 * 	REST to SOAP Wrapper.
 *	Invokes the SOAP API endpoint.
 *
 * 	Suvajit@Adobe.
 */

const Utils = require('../utils');

async function main (params) {
			
  try {
	const util = new Utils(params);	
	
	// Check if the Decrypted switch is set, if not set then init PGP options
	if (!params.decrypted || params.decrypted == 'N') {
		await util.initPGPKeys();			
	}
			
	let decryptedData={};
	
	if (params.decrypted && params.decrypted == 'Y') {
		decryptedData = JSON.parse(util.getPayloadData());
	}
	else {
		const data = util.getPayloadData();		
		decryptedData = JSON.parse(await util.decryptData(data));
	}

	const restResponse = await util.makeSoapCall(decryptedData);
	
	if (params.encryptResponse && params.encryptResponse == 'Y') {

		const encryptedData = await util.encryptData(JSON.stringify(restResponse));
	
		return {
		  statusCode: 200,
		  body: encryptedData
		}		
	}
	else {
		return {
		  statusCode: 200,
		  body: restResponse
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
