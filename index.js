'use strict';

var pem = require('pem');
var co = require('co');
var defaults = require('lodash.defaults');

// config = {
//   ttl: [duration until expiration, in seconds]
//   ca: {
//     cert: [CA certificate],
//     key: [CA key]
//   },
//   csr: {
//     country: [country],
//     state: [state],
//     locality: [locality],
//     organization: [organization],
//     organizationUnit: [organization unit],
//     emailAddress: [email address],
//   },
//   days: [days until certificate expires],
//   keyBitsize: [keybit size],
//   store: [data store]
// }
module.exports = function SSLGenerator(config) {
  let store = config.store;

  this.selfSigned = function (domain, options, fn) {
    if (typeof options === 'function') {
      fn = options;
      options = {};
    }

    co(function* () {
      var certKey = yield getCertKey(domain);
      if (certKey) {
        return certKey;
      } else {
        certKey = yield generateCertKey(domain ,options);
        yield setCertKey(domain, certKey, options.ttl || config.ttl);
        return certKey;
      }
    }).then(function (certKey) {
      fn(null, certKey);
    }, function (err) {
      fn(err);
    });
  };

  function generateCertKey(domain, options) {
    return new Promise(function (resolve, reject) {
      if (domain.startsWith('*')) {
        var altNames = [domain];
        domain = domain.split('.').slice(-2).join('.');
      }

      options = defaults(options, config);
      options.ca = defaults(options.ca, config.ca);
      options.csr = defaults(options.csr, config.csr);

      var pemOptions = {
        keyBitsize: options.keyBitsize || 2048,
        country: options.csr.country,
        state: options.csr.state,
        locality: options.csr.locality,
        organization: options.csr.organization,
        organizationUnit: options.csr.organizationUnit,
        commonName: domain,
        emailAddress: options.csr.emailAddress,
        serviceKey: options.ca.key,
        serviceCertificate: options.ca.cert,
        serial: Date.now(),
        days: options.days || 365
      };

      if (altNames && altNames.length > 0) {
        pemOptions.altNames = altNames;
      }

      pem.createCertificate(pemOptions, function (err, info) {
        if (err) {
          return reject(err);
        }
        return resolve({
          cert: info.certificate,
          key: info.clientKey
        });
      });
    });
  }

  function getCertKey(domain) {
    return new Promise(function (resolve, reject) {
      store.get(domain, function (err, certKey) {
        if (err) {
          return reject(err);
        }

        return resolve(certKey);
      });
    });
  }

  function setCertKey(domain, certKey, ttl) {
    return new Promise(function (resolve, reject) {
      let certKeyData = {
        domain: domain,
        cert: certKey.cert,
        key: certKey.key,
        ttl: ttl || config.ttl
      };

      store.set(certKeyData, function (err) {
        if (err) {
          return reject(err);
        }
        resolve();
      });
    });
  }
};