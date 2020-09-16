/*
* ACC Soap Specific settings
* Suvajit@ Adobe
* 
*/

const accSoapConfig = {
    attrPrefix : 'attr_',
    urnKeyword : 'urn:',
    namespaceStr : 'xmlns:urn',	
    soapNsStr : 'xmlns:soapenv',
    soapNsUrl : 'http://schemas.xmlsoap.org/soap/envelope/',
    soapEnvStr : 'soapenv:Envelope',
    soapBodyStr : 'soapenv:Body',	
    soapHeaderStr : 'soapenv:Header',
    sessionStr : 'urn:sessiontoken',
    valueKey : 'value',
    nsKeyword : 'ns:',
    soapEnvRespStr : 'SOAP-ENV:Envelope',
    soapBodyRespStr : 'SOAP-ENV:Body',
    soapFaultRespStr : 'SOAP-ENV:Fault',
    filterResponseElements : ['!','@','SOAP-ENV:encodingStyle', 'xsi:type', '_xmlns'],
    offerProposeSchema: 'nms:proposition',
    offerProposeMethod: 'Propose',
    offerPropositionUpdateSchema: 'nms:interaction',
    offerPropositionUpdateMethod: 'UpdateStatus'
};

module.exports = accSoapConfig;