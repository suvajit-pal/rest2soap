/*  
 * Helper action to get REST request format from SOAP
 *
 * Suvajit@Adobe.
*/

const Utils = require('../utils');

async function main (params) {

  try {
    // replace this with the api you want to access
    // if needed apikeys and tokens can be passed to the action using default parameters and dotenv variables

	const util = new Utils(params);
	
	const soapRequest = util.getSoapRequest();
	if (!soapRequest) {
		return {
		  'Content-Type': 'application/json',
		  statusCode: 500,
		  body: {
			error: 'Missing one or more required params : soapRequest'
		  }
		}	
	}
		
	return {
      statusCode: 200,
      body: util.getRestRequestFormat(soapRequest)
    }
  } catch (error) {
    return {
      statusCode: 500,
      body: { error: error.toString() }
    }
  }
}

exports.main = main
