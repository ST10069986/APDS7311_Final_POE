const forge = require('node-forge');
const fs = require('fs');

function generateSelfSignedCert() {
    const pki = forge.pki;
    const keys = pki.rsa.generateKeyPair(2048);
    const cert = pki.createCertificate();

    cert.publicKey = keys.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);

    const attrs = [{
        name: 'commonName',
        value: 'localhost'
    }, {
        name: 'countryName',
        value: 'US'
    }, {
        shortName: 'ST',
        value: 'State'
    }, {
        name: 'localityName',
        value: 'City'
    }, {
        name: 'organizationName',
        value: 'Test'
    }, {
        shortName: 'OU',
        value: 'Test'
    }];

    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.sign(keys.privateKey);

    fs.writeFileSync('cert.pem', pki.certificateToPem(cert));
    fs.writeFileSync('key.pem', pki.privateKeyToPem(keys.privateKey));

    console.log('SSL certificates generated successfully!');
}

generateSelfSignedCert();