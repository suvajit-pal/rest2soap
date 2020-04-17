/*
* Generic Utility Methods
* Suvajit@ Adobe
* This file exposes some common utilities for our actions 
*/

const { create, fragment, convert } = require('xmlbuilder2');

function Utils(params) { this.__params = params; }

/**
 * Returns a cleaned json structure for SOAP requests
 * @param {object} object to clean / sanitize.
 *
 * @returns {object} cleaned object
 */
Utils.prototype.cleanPropnames = function(obj) {
    for (var property in obj) {
        if (property === '!') delete obj[property];
		
		if (obj.hasOwnProperty(property)) {
			var newPropname;
			if (property.indexOf('urn:') >= 0) {
				newPropname = property.replace('urn:','');
				obj[newPropname] = obj[property];
				delete obj[property];
			}
			else 
				newPropname = property;
			
            if (typeof obj[newPropname] == "object")
                obj[newPropname] = this.cleanPropnames(obj[newPropname]);
        }
    }
	return obj;	
}

/**
 * Returns the pgp keys 
 *
 * @returns {object} The private key, public key and the password
 */
Utils.prototype.getPGPKeys = function() {
	const privateKeyArmored = this.__params.key ? this.__params.key : (Buffer.from(this.__params.f_key, 'base64')).toString('ascii');
	const publicKeyArmored = this.__params.public_key ? this.__params.public_key : (Buffer.from(this.__params.f_public_key, 'base64')).toString('ascii');
	const pass = this.__params.pass;
	
	return {privateKeyArmored: privateKeyArmored, publicKeyArmored: publicKeyArmored, secret: pass};
}

/**
 * Returns the payload data
 *
 * @returns {string} the payload data
 */
Utils.prototype.getPayloadData = function() {
	return this.__params.data ? this.__params.data : this.__params.__ow_body;
}

/**
 * Returns the payload data
 *
 * @returns {string} the soap payload data
 */
Utils.prototype.getSoapRequest = function() {
	return this.__params.soapRequest ? this.__params.soapRequest : this.__params['__ow_body'];
}

/**
 * Returns the SOAP request object 
 * @param {object} input rest object
 *
 * @returns {object} The SOAP request XML
 */
Utils.prototype.makeSoapObj = function (obj) {
	
	const firstElement = Object.getOwnPropertyNames(obj.payload)[0];
	let reqElemName = firstElement;
	let fragmentPayload = {};
	
	if (typeof obj.payload[firstElement] == "object") {
		reqElemName = 'urn:'+reqElemName;
		fragmentPayload[reqElemName] = obj.payload[Object.getOwnPropertyNames(obj.payload)[0]];
	}
	else {
		for (var prop in obj.payload) {
			fragmentPayload[prop] = obj.payload[prop];
		}
	}
	
	const frag = fragment({convert: {att: 'attr_'}}, fragmentPayload);
	
	const soapReq = create('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"></soapenv:Envelope>')
					.root().att('xmlns:urn', 'urn:'+obj.schema)
					.ele('soapenv:Header')
					.up().ele('soapenv:Body')
						.ele('urn:'+obj.method)
							.ele('urn:sessiontoken')
							.up().import(frag)
							.end();
							
	return soapReq;
}

/**
 * Returns the REST object 
 * @param {object} input soap object as xml
 *
 * @returns {object} REST object
 */
Utils.prototype.getRestRequestFormat = function (soapRequest) {
	
	const reqObject = convert({convert: {att: 'attr_'}}, soapRequest, {format: 'object'});
	const schemaName = reqObject['soapenv:Envelope']['attr_xmlns:urn'].replace('urn:','');
	const reqMethod = Object.getOwnPropertyNames(reqObject['soapenv:Envelope']['soapenv:Body'])[0].replace('urn:','');
	
	let requestPayload = reqObject['soapenv:Envelope']['soapenv:Body']['urn:'+reqMethod];
	delete  requestPayload['urn:sessiontoken'];
	
	return {schema: schemaName, method: reqMethod, 'securityToken': '**pass security token value**', 'sessionToken': '**pass session token**', payload: this.cleanPropnames(requestPayload)};
}
	
/**
 * Returns the JSON object after sanitization 
 * @param {object} input  object
 *
 * @returns {object} object sanitized of soap attributes
 */
Utils.prototype.cleanSoapPropNames = function (obj) {
    for (var property in obj) {
        if (property === '!' || property.indexOf('@') >= 0) delete obj[property];
		else {
			if (obj.hasOwnProperty(property)) {
				if (typeof obj[property] == "object"){
					obj[property] = this.cleanSoapPropNames(obj[property]);
					if (Object.getOwnPropertyNames(obj[property]).length == 0) delete obj[property];
				}
			}
			if (Array.isArray(obj[property])){
				obj[property] = obj[property].filter(function(e) {
					return e != null;
				});
				
				if (obj[property].length == 0) delete obj[property];
			}
		}
		
    }
	return obj;
}

/**
 * Returns the REST response 
 * @param {object} input soap xml
 * @param {string} the method that was invoked
 *
 * @returns {object} Response REST object sanitized of soap attributes
 */
Utils.prototype.getRestResponse = function (obj, method) {
	
	const response = convert({convert: {text: 'value'}}, obj, {format: 'object'});
	
	let restResponse = response['SOAP-ENV:Envelope']['SOAP-ENV:Body']['ns:'+method+'Response'];
	if (!restResponse || restResponse == undefined) {
		restResponse = response['SOAP-ENV:Envelope']['SOAP-ENV:Body']['SOAP-ENV:Fault'];
		if (!restResponse || restResponse == undefined) throw new Error(`Failed to parse response. Original response ${response}`);
	}
	restResponse = this.cleanSoapPropNames(restResponse);
	return restResponse;
}



/**
 *
 * Returns a log ready string of the action input parameters.
 * The `Authorization` header content will be replaced by '<hidden>'.
 *
 *
 * @returns {string}
 *
 */
Utils.prototype.stringParameters = function () {
  // hide authorization token without overriding params
  let headers = this.__params.__ow_headers || {}
  if (headers.authorization) {
    headers = { ...headers, authorization: '<hidden>' }
  }
  return JSON.stringify({ ...this.__params, __ow_headers: headers })
}

/**
 *
 * Returns the list of missing keys giving an object and its required keys.
 *
 * @param {object} obj object to check.
 * @param {array} required list of required keys.
 *        Each element can be multi level deep using a '.' separator e.g. 'myRequiredObj.myRequiredKey'
 *
 * @returns {array}
 * @private
 */
Utils.prototype.getMissingKeys = function (obj, required) {
  return required.filter(r => {
    const splits = r.split('.')
    const last = splits[splits.length - 1]
    const traverse = splits.slice(0, -1).reduce((tObj, split) => { tObj = (tObj[split] || {}); return tObj }, obj)
    return !traverse[last]
  })
}

/**
 *
 * Returns the list of missing keys giving an object and its required keys.
 * @param {array} requiredParams list of required input parameters.
 *        Each element can be multi level deep using a '.' separator e.g. 'myRequiredObj.myRequiredKey'.
 *
 * @returns {string} if the return value is not null, then it holds an error message describing the missing inputs.
 *
 */
Utils.prototype.checkMissingRequestInputs = function (requiredParams = [], requiredHeaders = []) {
  let errorMessage = null

  // input headers are always lowercase
  requiredHeaders = requiredHeaders.map(h => h.toLowerCase())
  // check for missing headers
  const missingHeaders = this.getMissingKeys(this.__params.__ow_headers || {}, requiredHeaders)
  if (missingHeaders.length > 0) {
    errorMessage = `missing header(s) '${missingHeaders}'`
  }

  // check for missing parameters
  const missingParams = this.getMissingKeys(requiredParams)
  if (missingParams.length > 0) {
    if (errorMessage) {
      errorMessage += ' and '
    } else {
      errorMessage = ''
    }
    errorMessage += `missing parameter(s) '${missingParams}'`
  }

  return errorMessage
}

/**
 *
 * Returns an error response object and attempts to log.info the status code and error message
 *
 * @param {number} statusCode the error status code.
 *        e.g. 400
 * @param {string} message the error message.
 *        e.g. 'missing xyz parameter'
 * @param {*} [logger] an optional logger instance object with an `info` method
 *        e.g. `new require('@adobe/aio-sdk').Core.Logger('name')`
 *
 * @returns {object} the error object, ready to be returned from the action main's function.
 *
 */
Utils.prototype.errorResponse = function (statusCode, message, logger) {
  if (logger && typeof logger.info === 'function') {
    logger.info(`${statusCode}: ${message}`)
  }
  return {
    error: {
      statusCode,
      body: {
        error: message
      }
    }
  }
}

module.exports = Utils;
