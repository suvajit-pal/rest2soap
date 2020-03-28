/*  */

/**
 * This is a sample action showcasing how to access an external service
 *
 * You can invoke this function via:
 *     aio rt:action:invoke <action_path>
 *
 * To find your <action_path>, run this command:
 *     aio rt:ls
 *
 * To show debug logging for this function, you can add the LOG_LEVEL parameter as well:
 *     aio rt:action:invoke <action_path> -p LOG_LEVEL '<log_level>'
 * ... where LOG_LEVEL can be one of [ error, warn, info, verbose, debug, silly ]
 *
 * Then, you can view your app logs:
 *     aio app:logs
 *
 * Secrets to access the external API can be passed to the action using default parameters and dotenv variables:
 *    - set MY_API_KEY=1234 in .env
 *    - configure the manifest.yml under `testConnection` to have an input field:
 *        inputs:
 *          myApiKey: $MY_API_KEY
 *    - access the apiKey in your action through params.myApiKey
 */

const { Core } = require('@adobe/aio-sdk')
const fetch = require('node-fetch')
const openpgp = require('@tripod/openpgp'); // check if dependencies are loaded

async function main (params) {
  // create a Logger
  const myAppLogger = Core.Logger('main', { level: params.LOG_LEVEL })
  // 'info' is the default level if not set
  myAppLogger.info('Calling the main action')

  // log levels are cumulative: 'debug' will include 'info' as well (levels are in order of verbosity: error, warn, info, verbose, debug, silly)
  myAppLogger.debug(`params: ${JSON.stringify(params, null, 2)}`) // careful to not log any secrets!

  try {
/*
const privateKeyArmored = `-----BEGIN PGP PRIVATE KEY BLOCK-----
....
-----END PGP PRIVATE KEY BLOCK-----`; // encrypted private key
    const passphrase = `secret`; 
*/

   // const { keys: [privateKey] } = await openpgp.key.readArmored(privateKeyArmored);
    //await privateKey.decrypt(passphrase);
/*
    const { data: decrypted } = await openpgp.decrypt({
        message: await openpgp.message.readArmored(params.data),            // parse armored message
        privateKeys: [privateKey]                                           // for decryption
    });
*/
    return {
      statusCode: 200,
      body: "Success"
    }
	console.log("Success");
  } catch (error) {
    myAppLogger.error(error)
    return {
      statusCode: 500,
      body: { error: JSON.stringify(error) }
    }
  }
}

exports.main = main
