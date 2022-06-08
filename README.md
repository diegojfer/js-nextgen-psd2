# JS-NextGen-PSD2 - XS2A

## What is PSD2?

According to [Wikipedia](https://en.wikipedia.org/wiki/Payment_Services_Directive), the Revised Payment Services Directive is an EU Directive, administered by the European Commission to regulate payment services and payment service providers throughout the European Union (EU) and European Economic Area (EEA).

## What is JS-NextGen-PSD2?

JS-NextGen-PSD2 is a [NodeJS](https://nodejs.org/en/) library to communicate with European Banks using NextGenPSD2 standard and PSD2 XS2A.

## What is NextGenPSD2? 

NextGenPSD2 is a european standard for PSD2 XS2A described by [The Berlin Group](https://www.berlin-group.org/). You can access to all technical documents on The Berlin Group's [download page](https://www.berlin-group.org/nextgenpsd2-downloads).


## How can I use JS-NextGen-PSD2?

Before using the module, you must request a valid eIDAS QWAC certificate from a [distinguish certificate authority](https://esignature.ec.europa.eu/efda/tl-browser/). 

### Simple Example

```javascript
const PSD2Client = require('js-nextgen-psd2')

let client = new PSD2Client(
    // Certificate and private key used for
    // signing requests.
    fs.readFileSync('SigningCertificate.cer'), 
    fs.readFileSync('SigningKey.pem'),
    {
        // Certificate and private key used 
        // for SSL client authentication.
        sslCertificate: fs.readFileSync('SSLCertificate.cer'),
        sslKey: fs.readFileSync('SSLPrivKey.pem'), 
        // HTTP request timeout
        timeout: 16000
    }
)

let response = await client.send(
    'post',
    'https://api.testbank.com/v1/consents',
    {
        'PSU-IP-Address': '192.168.8.78',
        'PSU-User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:54.0) Gecko/20100101 Firefox/54.0'
    }, 
    {
        access: {
            balances: [
                { iban: "DE40100100103307118608" },
                { iban: "DE02100100109307118603", currency: "USD" },
                { iban: "DE67100100101306118605" }
            ],
            transactions: [
                { iban: "DE40100100103307118608" },
                { maskedPan: "123456xxxxxx1234" }
            ]
        },
        recurringIndicator: true,
        validUntil: "2017-11-01",
        frequencyPerDay: "4"
    }
)
```
