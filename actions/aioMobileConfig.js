/*
* Country code settings to format mobile number 
* Ambily Mareena Cheriyan@Adobe
* Suvajit@Adobe
* 
* Supports customized numberValidator and asNull properties per country.
* numberValidate ==> A regexp (optional) which must match for a particular country.
* asNull ==> An array of string values (optional) which are considered as null.
* 
*/

module.exports = {
    aioMobileConfig: {
        TW: { length: 9, code: '886', numberValidator: '(^09\\d{8}$)|(^\\+0\\()|(^\\+?886)', asNull: ['NOTMAPPED', 'NULL', 'N/A'] },
        IN: { length: 10, code: '91' },
        SG: { length: 8, code: '65' },
        default_country: 'TW',
        asNull: ['NOTMAPPED', 'NULL', 'N/A']
    }
}