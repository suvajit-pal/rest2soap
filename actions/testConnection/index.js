/*
 * Test connection 
 * 	Checks Connection.
 *	Validate Encryption Keys.
 * 	Validate Decryption Keys.
 *
 *	Suvajit@Adobe.
 */

const Utils = require('../utils');
	
async function main (params) {
  const util = new Utils(params);
  
  try {
	
	// if PGP encryption or decryption check is set to Y,
	// initilaize the PGP parameters
	if (params.checkDecryption && params.checkDecryption == 'Y' || params.checkEncryption && params.checkEncryption == 'Y') {
		await util.initPGPKeys();		
	}
	
	if (params.checkDecryption && params.checkDecryption == 'Y') {
		const data = util.getPayloadData();		
		
		if (!data) {
			return {
				'Content-Type': 'application/json',
				statusCode: 500,
				body: {
					error: 'Missing encrypted payload data.'
				}
			}		
		}		

		const decryptedData = await util.decryptData(data);
			
		return {
			statusCode: 200,
			body: decryptedData
		}

	}
	else if (params.checkEncryption && params.checkEncryption == 'Y') {
		const returnMsg = {message: "This is a test message from Adobe @ " + new Date()};
		
		const encryptedData = await util.encryptData(returnMsg);		
		
		return {
		  'Content-Type': 'text/plain',
		  statusCode: 200,
		  body: encryptedData
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
      body: { error: error.message, code: error.code }
    }
  }
}

exports.main = main
