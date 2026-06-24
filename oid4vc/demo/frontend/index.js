import express from "express";

import axios from "axios";

import { v4 as uuidv4 } from "uuid";
import {default as NodeCache } from "node-cache";
import QRCode from "qrcode-svg";

import path from "node:path";

import pino from "pino";
import colada from "pino-colada";

import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { EventEmitter } from 'node:events';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ##        #######   ######    ######   ######## ########
// ##       ##     ## ##    ##  ##    ##  ##       ##     ##
// ##       ##     ## ##        ##        ##       ##     ##
// ##       ##     ## ##   #### ##   #### ######   ########
// ##       ##     ## ##    ##  ##    ##  ##       ##   ##
// ##       ##     ## ##    ##  ##    ##  ##       ##    ##
// ########  #######   ######    ######   ######## ##     ##
// Setup the Pino Logger

const logger_stream = {
  formatter: colada(),
  console: (level, msg) => {
    if (level <= 30)
      process.stdout.write(msg);
    else
      process.stderr.write(msg);
  },
  write: function(msg) {
    msg = JSON.parse(msg);
    let level = msg["level"] ?? 30;
    msg = this.formatter(msg);
    if (msg.length > 0) {
      this.console(level, msg);
    }
  },
}

const logger = pino({
  prettifier: colada,
  level: 'trace',
}, logger_stream);

// ######## ##     ## ########  ########  ########  ######   ######
// ##        ##   ##  ##     ## ##     ## ##       ##    ## ##    ##
// ##         ## ##   ##     ## ##     ## ##       ##       ##
// ######      ###    ########  ########  ######    ######   ######
// ##         ## ##   ##        ##   ##   ##             ##       ##
// ##        ##   ##  ##        ##    ##  ##       ##    ## ##    ##
// ######## ##     ## ##        ##     ## ########  ######   ######
// Setup the Express app

const app = express();
app.set("views", path.join(__dirname, "templates"));
app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: false}));
app.use(express.json());
app.use(express.static("public"));

const events = new EventEmitter();
const exchangeCache = new NodeCache({ stdTTL: 300, checkperiod: 400 });
const presentationCache = new NodeCache({ stdTTL: 300, checkperiod: 400 });

const API_BASE_URL = process.env.API_BASE_URL || "http://localhost:3001";
const API_KEY = process.env.API_KEY;
const KEYCLOAK_NGROK_URL = process.env.KEYCLOAK_NGROK_URL;
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || "acapy-issuer";
const KEYCLOAK_CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET || "acapy-issuer-secret";
const KEYCLOAK_USER = process.env.KEYCLOAK_USER || "demo-user";
const KEYCLOAK_PASSWORD = process.env.KEYCLOAK_PASSWORD || "demo-password";
const KEYCLOAK_REALM = "oid4vc-demo";

//certificate and private key to import for mDL issuance
//expires 2036, private_key is PEM base64 encoded PKCS #8.
//TODO the certifciate does not work for verification as a trust anchor - IACA extensions are missing.
const certificate_pem = "-----BEGIN CERTIFICATE-----\nMIIB1DCCAXmgAwIBAgIIdNRHwTfOGwcwCgYIKoZIzj0EAwIwDTELMAkGA1UEBhMC\nQ0EwHhcNMjYwNDEzMTkyNDAwWhcNMzYwNDEzMTkyNDAwWjANMQswCQYDVQQGEwJD\nQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNKdpd24SPAyNLWNd4J/hlEU5awn\nh26s4sQnJ6cy5tzF92eoNCoz/RKeUD2pCUStdJhN3qYnXgnMbDqLlGIt0bmjgcIw\ngb8wEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUQHLNvJUIYoRcUOiu5qhb\nvaxt4UgwDgYDVR0PAQH/BAQDAgEGMCIGA1UdEgQbMBmGF21haWx0bzp1c2VyQGV4\nYW1wbGUuY29tMCMGA1UdHwQcMBowGKAWoBSGEmh0dHA6Ly9leGFtcGxlLmNvbTAR\nBglghkgBhvhCAQEEBAMCAAcwHgYJYIZIAYb4QgENBBEWD3hjYSBjZXJ0aWZpY2F0\nZTAKBggqhkjOPQQDAgNJADBGAiEA0zfq5zFY1hz9E//K9n/JlcVDZ+WN1bTduq8u\n/MXtoPkCIQCQw3KbsNB9e/2yskidmuJe5CdFK3VvZpw0SC8IsG2H5A==\n-----END CERTIFICATE-----\n";
const private_key_pem = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6Al13xaXxheg2tsc\nIQEdUKWRqaCAdcHCfPxw6+yTufWhRANCAATSnaXduEjwMjS1jXeCf4ZRFOWsJ4du\nrOLEJyenMubcxfdnqDQqM/0SnlA9qQlErXSYTd6mJ14JzGw6i5RiLdG5\n-----END PRIVATE KEY-----\n";
let jwtVcSupportedCredCreated = false;
let sdJwtSupportedCredCreated = false;
let mdocSupportedCredCreated = false;
let sdJwtStatusListCreated = false;
let jwtStatusListCreated = false;
let jwtVcSupportedCredID = "";
let sdJwtSupportedCredID = "";
let mdocSupportedCredID = "";
let jwtStatusListID = "";
let sdJwtStatusListID = "";


//    ###     ######     ###            ########  ##    ##
//   ## ##   ##    ##   ## ##           ##     ##  ##  ##
//  ##   ##  ##        ##   ##          ##     ##   ####
// ##     ## ##       ##     ## ####### ########     ##
// ######### ##       #########         ##           ##
// ##     ## ##    ## ##     ##         ##           ##
// ##     ##  ######  ##     ##         ##           ##
// ACA-Py related controller helper functions

// Begin Issue JWT Credential Flow
async function issue_jwt_credential(req, res) {
  res.status(200).send("");
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Received credential data from user."});

  const { fname: firstName, lname: lastName, email } = req.body

  const headers = {
    accept: "application/json",
  };
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }
  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;


  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };


  // Create credential schema
  const createCredentialSupportedUrl = `${API_BASE_URL}/oid4vci/credential-supported/create/jwt`;
  const createCredentialSupportedOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      cryptographic_binding_methods_supported: ["did"],
      credential_signing_alg_values_supported: ["ES256"],
      format: "jwt_vc_json",
      id: "UniversityDegreeCredential",
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: ["ES256"]
        }
      },
      credential_definition: {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1",
        ],
        type: [
          "VerifiableCredential",
          "UniversityDegreeCredential"
        ],
      },
      credential_metadata: {
        display: [
          {
            name: "University Credential",
            locale: "en-US",
            logo: {
             url: "https://w3c-ccg.github.io/vc-ed/plugfest-1-2022/images/JFF_LogoLockup.png",
              alt_text: "a square logo of a university",
            },
            background_color: "#12107c",
            text_color: "#FFFFFF",
            background_image: {
              uri: "data:image/png;base64,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",
              alt_text: "University credential background",
            },
          },
        ],
        claims: [
          {
             path: [
              "degree"
             ],
             display: [
                {
                  name: "Degree",
                  locale: "en-US",
                },
             ],
          },
          {
            path: [
              "given_name"
            ],
            display: [
              {
                name: "Given Name",
                locale: "en-US",
              },
            ],
          },
          {
            path: [
              "gpa"
            ],
            display: [
              {
                name: "GPA Score",
                locale: "en-US",
              },
            ],
          },
          {
            path: [
              "last_name"
            ],
            display: [
              {
                name: "Surname",
                locale: "en-US",
              },
            ],
          },
        ],
      },
    }),
  };

  if (!jwtVcSupportedCredCreated){
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Create Credential Request to: ${createCredentialSupportedUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: createCredentialSupportedOptions});
    const supportedCredentialData = await fetchApiData(
      createCredentialSupportedUrl,
      createCredentialSupportedOptions
    );
    jwtVcSupportedCredID = supportedCredentialData.supported_cred_id;
    jwtVcSupportedCredCreated = true;
  }

   logger.info(jwtVcSupportedCredID);

  // Create bitstring status list Configuration
  const statusListCreateUrl = `${API_BASE_URL}/status-list/defs`;
  const statusListCreateOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      issuer_did: issuerDID,
      list_size: 131072,
      list_type: "w3c",
      shard_size: 131072,
      status_message: [
        {
            status: "0x00",
            message: "active"
        },
        {
            status: "0x01",
            message: "inactive"
        },
    ],
    status_purpose: "revocation",
    status_size: 1,
    supported_cred_id: jwtVcSupportedCredID,
    verification_method: issuerDID+"#0"
    })
  };

  if (!jwtStatusListCreated){
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Create Status List Request to: ${statusListCreateUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: statusListCreateOptions});
    const statusListResponse = await fetchApiData(statusListCreateUrl, statusListCreateOptions);
    jwtStatusListID = statusListResponse.id;
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Created Status List ID: ${jwtStatusListID}`});
    jwtStatusListCreated = true;
  };

  // Create Credential Exchange records
  const exchangeCreateUrl = `${API_BASE_URL}/oid4vci/exchange/create`;
  const exchangeCreateOptions = {
    credential_subject: { id: req.body.registrationId, first_name: firstName, last_name: lastName, email },
    did: issuerDID,
    verification_method: issuerDID+"#0",
    supported_cred_id: jwtVcSupportedCredID,
    notification_id: "123456"
  };
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Generating Credential Exchange."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Credential Exchange Creation Request to: ${exchangeCreateUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: exchangeCreateOptions});
  const exchangeResponse = await axios.post(exchangeCreateUrl, exchangeCreateOptions, { headers: commonHeaders });
  const exchangeId = exchangeResponse.data.exchange_id;
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Received Credential Exchange ID: ${exchangeId}`});


  // Get Credential Offer information
  const credentialOfferUrl = `${API_BASE_URL}/oid4vci/credential-offer`;
  const queryParams = {
    user_pin_required: false,
    exchange_id: exchangeId,
  };
  const credentialOfferOptions = {
    params: queryParams,
    headers: commonHeaders,
  };
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Requesting Credential Offer."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Retrieving Credential Offer from: ${credentialOfferUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: credentialOfferOptions});
  const offerResponse = await axios.get(credentialOfferUrl, credentialOfferOptions);
  const credentialOffer = offerResponse.data;

  // Generate QRCode and send it to the browser via HTMX events
  logger.info(JSON.stringify(offerResponse.data));
  logger.info(exchangeId);
  
  let qrcode;
  if (credentialOffer.hasOwnProperty("credential_offer")) {
    // credential offer is passed by value
    qrcode = credentialOffer.credential_offer
  } else {
    // credential offer is passed by reference, and the wallet must dereference it using the
    // /oid4vci/dereference-credential-offer endpoint
    qrcode = credentialOffer.credential_offer_uri
  }

  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Sending offer to user: ${qrcode}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "qrcode", credentialOffer, exchangeId, qrcode});
  exchangeCache.set(exchangeId, { exchangeId, credentialOffer, did: issuerDID, jwtVcSupportedCredID, registrationId: req.body.registrationId });

  // Polling for the credential is an option at this stage, but we opt to just listen for the appropriate webhook instead
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Begin listening for credential to be issued."});
}


// Begin Issue SD-JWT Credential Flow
async function issue_sdjwt_credential(req, res) {
  res.status(200).send("");
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Received credential data from user."});

  const { fname: firstName, lname: lastName, age: ageString } = req.body
  const age = parseInt(ageString);

  const headers = {
    accept: "application/json",
  };
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }
  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;

  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };


  // Create credential schema
  const createCredentialSupportedUrl = `${API_BASE_URL}/oid4vci/credential-supported/create/sd-jwt`;
  const createCredentialSupportedOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      format: "vc+sd-jwt",
      id: "IDCard",
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: [
            "ES256"
          ]
        }
      },
      cryptographic_binding_methods_supported: ["jwk"],
      credential_signing_alg_values_supported: ["ES256K"],
      vct: "ExampleIDCard",
      sd_list: [
          "/given_name",
          "/family_name",
          "/age_is_over_12",
          "/age_is_over_14",
          "/age_is_over_16",
          "/age_is_over_18",
          "/age_is_over_21",
          "/age_is_over_65"
        ],
      credential_metadata: {  
        display: [
          {
            "name": "ID Card",
            "locale": "en-US",
            "background_color": "#12107c",
            "text_color": "#FFFFFF",
            "background_image": {
              "uri": "data:image/png;base64,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",
              "alt_text": "ID card background"
            }
          }
        ],
        "claims": [
          {
          "path": ["given_name"],
          "display": [
            {
              "name": "Given Name",
              "locale": "en-US"
            }
          ]
          },
          {
            "path": ["family_name"],
            "display": [
              {
                "name": "Family Name",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["something_nested", "key1", "key2", "key3"],
            "display": [
              {
                "name": "Something Nested",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["is_over_12"],
            "display": [
              {
                "name": "Age 12 or Over",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["is_over_14"],
            "display": [
              {
                "name": "Age 14 or Over",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["is_over_16"],
            "display": [
              {
                "name": "Age 16 or Over",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["is_over_18"],
            "display": [
              {
                "name": "Age 18 or Over",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["is_over_21"],
            "display": [
              {
                "name": "Age 21 or Over",
                "locale": "en-US"
              }
            ]
          },
          {
            "path": ["is_over_65"],
            "display": [
              {
                "name": "Age 65 or Over",
                "locale": "en-US"
              }
            ]
          }
        ],
      }
    }),
  };

  if (!sdJwtSupportedCredCreated){

    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Create Credential Request to: ${createCredentialSupportedUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: createCredentialSupportedOptions});
    const supportedCredentialData = await fetchApiData(
      createCredentialSupportedUrl,
      createCredentialSupportedOptions
    );
    sdJwtSupportedCredID = supportedCredentialData.supported_cred_id;
    sdJwtSupportedCredCreated = true;
  }

  logger.info(sdJwtSupportedCredID);

  // Create IETF Token status list Configuration
  const statusListCreateUrl = `${API_BASE_URL}/status-list/defs`;
  const statusListCreateOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      issuer_did: issuerDID,
      list_size: 131072,
      list_type: "ietf",
      shard_size: 131072,
      status_message: [
        {
            status: "0x00",
            message: "active"
        },
        {
            status: "0x01",
            message: "inactive"
        },
    ],
    status_purpose: "revocation",
    status_size: 1,
    supported_cred_id: sdJwtSupportedCredID,
    verification_method: issuerDID+"#0"
    })
  };

  if (!sdJwtStatusListCreated){
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Create Status List Request to: ${statusListCreateUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: statusListCreateOptions});
    const statusListResponse = await fetchApiData(statusListCreateUrl, statusListCreateOptions);
    sdJwtStatusListID = statusListResponse.id;
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Created Status List ID: ${sdJwtStatusListID}`});
    sdJwtStatusListCreated = true;
  };

  const isRefresh = req.body['is-refresh'] === 'on';
  const refreshId = req.body['refresh-id'];

  const exchangeCreateOptions = {
    did: issuerDID,
    verification_method: issuerDID+"#0",
    supported_cred_id: sdJwtSupportedCredID,
    credential_subject: {
      given_name: firstName,
      family_name: lastName,
      something_nested: {key1: {key2: {key3: "something nested"}}},
      source_document_type: "id_card",
      age_is_over_12: true,
      age_is_over_14: true,
      age_is_over_16: true,
      age_is_over_18: true,
      age_is_over_21: true,
      age_is_over_65: false,
    },
  };
  
  let exchangeId;
  if (isRefresh) {
    const refreshUrl = `${API_BASE_URL}/oid4vci/credential-refresh/${refreshId}`;
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Credential Refresh Request to: ${refreshUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: exchangeCreateOptions});
    const exchangeResponse = await axios.patch(refreshUrl, exchangeCreateOptions, { headers: commonHeaders });
    exchangeId = exchangeResponse.data.exchange_id;
  } else {
    const exchangeCreateUrl = `${API_BASE_URL}/oid4vci/exchange/create`;
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Generating Credential Exchange."});
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Credential Exchange Creation Request to: ${exchangeCreateUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: exchangeCreateOptions});
    const exchangeResponse = await axios.post(exchangeCreateUrl, exchangeCreateOptions, { headers: commonHeaders });
    exchangeId = exchangeResponse.data.exchange_id;
  }
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Received Credential Exchange ID: ${exchangeId}`});


  if (!isRefresh) {
    // Get Credential Offer information
    const credentialOfferUrl = `${API_BASE_URL}/oid4vci/credential-offer-by-ref`;
    const queryParams = {
      user_pin_required: false,
      exchange_id: exchangeId,
    };
    const credentialOfferOptions = {
      params: queryParams,
      headers: commonHeaders,
    };
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Requesting Credential Offer."});
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Retrieving Credential Offer from: ${credentialOfferUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: credentialOfferOptions});
    const offerResponse = await axios.get(credentialOfferUrl, credentialOfferOptions);
    const credentialOffer = offerResponse.data;

    // Generate QRCode and send it to the browser via HTMX events
    logger.info(JSON.stringify(offerResponse.data));
    logger.info(exchangeId);

    let qrcode;
    if (credentialOffer.hasOwnProperty("credential_offer")) {
      // credential offer is passed by value
      qrcode = credentialOffer.credential_offer
    } else {
      // credential offer is passed by reference, and the wallet must dereference it using the
      // /oid4vci/dereference-credential-offer endpoint
      qrcode = credentialOffer.credential_offer_uri
    }

    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Sending offer to user: ${qrcode}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "qrcode", credentialOffer, exchangeId, qrcode});
    exchangeCache.set(exchangeId, { exchangeId, credentialOffer, issuerDID, sdJwtSupportedCredID, registrationId: req.body.registrationId });

    // Polling for the credential is an option at this stage, but we opt to just listen for the appropriate webhook instead
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Begin listening for credential to be issued."});
  } else {
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Credential Refresh API call was successful."});
  }
}

// Begin Issue mDL (mso_mdoc) Credential Flow
async function issue_mdoc_credential(req, res) {
  res.status(200).send("");
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Received mDL credential data from user."});

  console.log("req.body", req.body);
  const {
    family_name,
    given_name,
    birth_date,
    issue_date,
    expiry_date,
    issuing_authority,
    document_number,
    issuing_country,
    un_distinguishing_sign,
    portrait,
  } = req.body;

  const headers = {
    accept: "application/json",
  };
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }

  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;


  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };

  const createCredentialSupportedUrl = `${API_BASE_URL}/oid4vci/credential-supported/create/mso-mdoc`;
  const createCredentialSupportedOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      format: "mso_mdoc",
      id: "org.iso.18013.5.1.mDL",
      doctype: "org.iso.18013.5.1.mDL",
      signing_key_id: mdocKeyId,
      cryptographic_binding_methods_supported: ["jwk"],
      credential_signing_alg_values_supported: [
        "ES256"
      ],
      proof_types_supported: {
        jwt: {
          proof_signing_alg_values_supported: [
            "ES256"
          ]
        }
      },
      "credential_metadata": {
        claims: [
          { path: ["org.iso.18013.5.1", "given_name"], display: [{ name: "Given Name", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "family_name"], display: [{ name: "Family Name", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "birth_date"], display: [{ name: "Birth Date", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "issue_date"], display: [{ name: "Issue Date", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "expiry_date"], display: [{ name: "Expiry Date", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "issuing_authority"], display: [{ name: "Issuing Authority", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "document_number"], display: [{ name: "Document Number", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "issuing_country"], display: [{ name: "Issuing Country", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "un_distinguishing_sign"], display: [{ name: "UN Distinguishing Sign", locale: "en-US" }] },
          { path: ["org.iso.18013.5.1", "portrait"], display: [{ name: "Portrait", locale: "en-US" }] }
        ],
        display: [
          {
            name: "Sample Driving License",
            locale: "en-US",
            background_image: {
              uri: "data:image/png;base64,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TXpm3KRnBvbu0qhBvejtpRaJanFyk5OaNFqwbO3C5et6dWlb1quOvZaSz57Mq4s9fOHydd07tAwhnHZi45ycbCkIkIZBGML899dc0Kl1COGCTq3nL11bdGrAM16au2zbZzvzPtv1yvzlZ7c+fAqIUu9auX7zqg1bip2vYs6iVR3bNP9Sg/q9urSbs3j1wYMHu3Vo1bld84f+44bf3j20Z+c2p5x4QghhxUf/+mDdJ7v3frFu06eNjq8Xe/i5Z7V4672V2z7b+en2z3983/TPi04LVWqRqD7d2y9YuqagoHDuktUXdm6TzJnoiz178q8uhLBw+Ued27XIzsrqdnbLd5au82sHENLxu0a3f777811727Q4qUOrUyfPmB0dSOVkZxcWFoaiUwPuLyg8XLq0uwpK+27SvB27Vq3f3Ltbux4dz/zF5OdDCNnZWTNeWzjjtYXx00/27PsiHPo+zxB/YK9unZxde/aF0r4cvFiRQ+GfFenVtd0JDev3KzopRJezznj3g49CCJFwqG6DesXPZVHs2ZN/ddEXuCXv8/atTuneoeVfXpzv1w4gXdsn5i9dO+ya3svXbop91/YH6z75cs+OTb7UoOkJDfpfcPbiFRsOHgx16+RkZ2eVvCtB5bcXrRrcv0feZzs3bM4LISxfu+niru1OatLoSw3q3zls4MVd2yV47PI1m/qe16FRg3qnn9T4N/85pEHR+ZjKKtK5XYuCwsIRYycPH/2n4aP/9PLcpdG7du/9ouVpzRo1qNexzentW50Szbzoayn5pMm8uviHL1y+rk/39k1PaLD64y1+7QDSNQjfWbq25anNYvtFQwhvvbdy5frNE3/4tVHf+cq899csWrFhx6492z/fPfKWr5S8K0HlBcvWZmVF3l60Kvrj4hUb3nx35ejvXvtft/3bhs15cxavSvDYtxatXLdx6323feOOYQOfeGFebHRYVpE+3c56Zd6yAwcO7cF87Z0PunVoWf+4OivXb16zcesvb//mNf26L/zgoxBC7LWU8qRJvLr4h/9z+bqLu541b8ma0k5jDEBw9onaLDsrK5IVufdH193zp+c+K6PtBIBwLM4+kePtqAbnd2o94tq+f31pvhQECOk7WYZKm7dk9bwlq70PAMF3jQKAIAQAQQgAghAABCEACEIACMe6fSLaYAgARoQAEDLoK9YAwIgQADLO/wdRaDutoxb+DgAAAABJRU5ErkJggg==",
              alt_text: "Driver's license background",
            },
          },
        ],
      },
    }),
  };

  if (!mdocSupportedCredCreated) {
    events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Create Credential Request to: ${createCredentialSupportedUrl}`});
    events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: createCredentialSupportedOptions});
    console.log("Creating mDL supported credential", createCredentialSupportedOptions);
    const supportedCredentialData = await fetchApiData(
      createCredentialSupportedUrl,
      createCredentialSupportedOptions
    );
    mdocSupportedCredID = supportedCredentialData.supported_cred_id;
    mdocSupportedCredCreated = true;
  }

  logger.info(mdocSupportedCredID);
  
  // Create credential exchange
  const exchangeCreateUrl = `${API_BASE_URL}/oid4vci/exchange/create`;
 
  console.log("FAMILY NAME", family_name);
  const exchangeCreateOptions = {
      supported_cred_id: mdocSupportedCredID,
      credential_subject: {
        "org.iso.18013.5.1": {
          family_name,
          given_name,
          birth_date,
          issue_date,
          expiry_date,
          issuing_country,
          issuing_authority,
          document_number,
          portrait,
          un_distinguishing_sign,
        }
      },
      verification_method: issuerDID + "#0",
  };

  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Generating Credential Exchange."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Posting Credential Exchange Creation Request to: ${exchangeCreateUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: exchangeCreateOptions});
  
  const exchangeResponse = await axios.post(exchangeCreateUrl, exchangeCreateOptions, { headers: commonHeaders });
  const exchangeId = exchangeResponse.data.exchange_id;
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Received Credential Exchange ID: ${exchangeId}`});


  // Get credential offer and emit QR code as in other flows
  const credentialOfferUrl = `${API_BASE_URL}/oid4vci/credential-offer-by-ref`;
  const queryParams = {
    exchange_id: exchangeId,
    user_pin_required: false,
  };

  const credentialOfferOptions = {
    params: queryParams,
    headers: commonHeaders,
  };
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Requesting Credential Offer."});
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Retrieving Credential Offer from: ${credentialOfferUrl}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "debug-message", message: "Request options", data: credentialOfferOptions});
  const offerResponse = await axios.get(credentialOfferUrl, credentialOfferOptions);
  const credentialOffer = offerResponse.data;
  
  let qrcode;
  if (credentialOffer.credential_offer) {
    qrcode = credentialOffer.credential_offer;
  } else {
    qrcode = credentialOffer.credential_offer_uri;
  } 
  logger.info(JSON.stringify(offerResponse.data));
  logger.info(exchangeId);
  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: `Sending offer to user: ${qrcode}`});
  events.emit(`issuance-${req.body.registrationId}`, {type: "qrcode", credentialOffer, exchangeId, qrcode});
  exchangeCache.set(exchangeId, { exchangeId, credentialOffer, mdocSupportedCredID, registrationId: req.body.registrationId });

  events.emit(`issuance-${req.body.registrationId}`, {type: "message", message: "Begin listening for credential to be issued."});
}

// Begin JWT VC JSON Presentation Flow
async function create_jwt_vc_presentation(req, res) {
  const presentationId = req.params.id;
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }
  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;


  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };


  // Create Presentation Definition
  events.emit(`presentation-${presentationId}`, {type: "message", message: "Creating Presentation Definition."});
  const presentationDefinition = {"pres_def": {
    "id": uuidv4(),
    "purpose": "Present basic profile info",
    "format": {
      "jwt_vc_json": {
        "alg": [
          "ES256"
        ]
      },
      "jwt_vp_json": {
        "alg": [
          "ES256"
        ]
      },
      "jwt_vc": {
        "alg": [
          "ES256"
        ]
      },
      "jwt_vp": {
        "alg": [
          "ES256"
        ]
      }
    },
    "input_descriptors": [
      {
        "id": "4ce7aff1-0234-4f35-9d21-251668a60950",
        "name": "Profile",
        "purpose": "Present basic profile info",
        "constraints": {
          "fields": [
            {
              "name": "name",
              "path": [
                "$.vc.credentialSubject.first_name",
                "$.credentialSubject.first_name"
              ],
              "filter": {
                "type": "string",
                "pattern": "^.{1,64}$"
              }
            },
            {
              "name": "lastname",
              "path": [
                "$.vc.credentialSubject.last_name",
                "$.credentialSubject.last_name"
              ],
              "filter": {
                "type": "string",
                "pattern": "^.{1,64}$"
              }
            }
          ]
        }
      }
    ]
  }
  };

  const presentationDefinitionUrl = `${API_BASE_URL}/oid4vp/presentation-definition`;
  const presentationDefinitionOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify(presentationDefinition),
  };
  logger.warn(presentationDefinitionUrl);
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting Presentation Definition to: ${presentationDefinitionUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: presentationDefinitionOptions});
  const presentationDefinitionData = await fetchApiData(
    presentationDefinitionUrl,
    presentationDefinitionOptions
  );
  logger.info("Created presentation?");
  logger.trace(JSON.stringify(presentationDefinitionData));
  logger.trace(presentationDefinitionData.pres_def_id);
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Created Presentation Definition`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Presentation Definition ID: ${presentationDefinitionData.pres_def_id}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: presentationDefinitionData});


  // Create Presentation Request
  const presentationRequestUrl = `${API_BASE_URL}/oid4vp/request`;
  const presentationRequestOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      "pres_def_id": presentationDefinitionData.pres_def_id,
      "vp_formats": {
        "jwt_vc": { "alg": [ "ES256", "EdDSA" ] },
        "jwt_vp": { "alg": [ "ES256", "EdDSA" ] },
        "jwt_vc_json": { "alg": [ "ES256", "EdDSA" ] },
        "jwt_vp_json": { "alg": [ "ES256", "EdDSA" ] }
      },
    }),
  };
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generating Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting Presentation Request to: ${presentationRequestUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: presentationRequestOptions});
  const presentationRequestData = await fetchApiData(
    presentationRequestUrl,
    presentationRequestOptions
  );
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generated Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Presentation Request URI: ${presentationRequestData?.request_uri}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: presentationRequestData});

  // Grab the relevant data and store it for later reference while waiting for the webhooks from ACA-Py
  let code = presentationRequestData.request_uri;
  presentationCache.set(presentationDefinitionData.pres_def_id, { presentationDefinitionData, presentationRequestData, presentationId: presentationId });
  logger.trace(JSON.stringify(presentationRequestData, null, 2));

  // Generate a QRCode and return it to the browser (HTMX replaces a div with our current response)
  var qrcode = new QRCode({
    content: code,
    padding: 4,
    width: 256,
    height: 256,
    color: "#000000",
    background: "#ffffff",
    ecl: "M",
  });
  qrcode = qrcode.svg()
  qrcode = qrcode.substring(qrcode.indexOf('?>')+2,qrcode.length)
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(qrcode);

  // Polling for the credential is an option at this stage, but we opt to just listen for the appropriate webhook instead
}

// Begin SD-JWT Presentation Flow
async function create_sd_jwt_presentation(req, res) {
  const presentationId = req.params.id;
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }
  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;


  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };


  // Create Presentation Definition
  events.emit(`presentation-${presentationId}`, {type: "message", message: "Creating Presentation Definition."});
  const presentationDefinition = {"pres_def": {
    "id": uuidv4(),
    "purpose": "Present basic profile info",
    "input_descriptors": [
      {
        "format": {
          "vc+sd-jwt": {}
        },
        "id": "ID Card",
        "name": "Profile",
        "purpose": "Present basic profile info",
        "constraints": {
          "limit_disclosure": "required",
          "fields": [
            {
              "path": [
                "$.vct"
              ],
              "filter": {
                "type": "string"
              }
            },
            {
              "path": [
                "$.family_name"
              ]
            },
            {
              "path": [
                "$.given_name"
              ]
            },
            {
              "path": [
                "$.something_nested.key1.key2.key3"
              ]
            },
          ]
        }
      }
    ]
  }};

  const presentationDefinitionUrl = `${API_BASE_URL}/oid4vp/presentation-definition`;
  const presentationDefinitionOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify(presentationDefinition),
  };
  logger.warn(presentationDefinitionUrl);
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting Presentation Definition to: ${presentationDefinitionUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: presentationDefinitionOptions});
  const presentationDefinitionData = await fetchApiData(
    presentationDefinitionUrl,
    presentationDefinitionOptions
  );
  logger.info("Created presentation?");
  logger.trace(JSON.stringify(presentationDefinitionData));
  logger.trace(presentationDefinitionData.pres_def_id);
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Created Presentation Definition`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Presentation Definition ID: ${presentationDefinitionData.pres_def_id}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: presentationDefinitionData});


  // Create Presentation Request
  const presentationRequestUrl = `${API_BASE_URL}/oid4vp/request`;
  const presentationRequestOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      "pres_def_id": presentationDefinitionData.pres_def_id,
      "vp_formats": {
        "vc+sd-jwt": {
            "sd-jwt_alg_values": [
                "ES256",
                "ES384"
            ],
            "kb-jwt_alg_values": [
                "ES256",
                "ES384"
            ]
        }
      },
    }),
  };
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generating Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting Presentation Request to: ${presentationRequestUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: presentationRequestOptions});
  const presentationRequestData = await fetchApiData(
    presentationRequestUrl,
    presentationRequestOptions
  );
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generated Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Presentation Request URI: ${presentationRequestData?.request_uri}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: presentationRequestData});

  // Grab the relevant data and store it for later reference while waiting for the webhooks from ACA-Py
  let code = presentationRequestData.request_uri;
  presentationCache.set(presentationDefinitionData.pres_def_id, { presentationDefinitionData, presentationRequestData, presentationId: presentationId });
  logger.trace(JSON.stringify(presentationRequestData, null, 2));

  // Generate a QRCode and return it to the browser (HTMX replaces a div with our current response)
  var qrcode = new QRCode({
    content: code,
    padding: 4,
    width: 256,
    height: 256,
    color: "#000000",
    background: "#ffffff",
    ecl: "M",
  });
  qrcode = qrcode.svg()
  qrcode = qrcode.substring(qrcode.indexOf('?>')+2,qrcode.length)
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(qrcode);

  // Polling for the credential is an option at this stage, but we opt to just listen for the appropriate webhook instead
}

// Begin mDOC Presentation Flow (DCQL)
async function create_mdoc_presentation(req, res) {
  const presentationId = req.params.id;
  const commonHeaders = {
    accept: "application/json",
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token.token,
  };
  if (API_KEY) {
    commonHeaders["X-API-KEY"] =  API_KEY;
  }
  axios.defaults.withCredentials = true;
  axios.defaults.headers.common["Access-Control-Allow-Origin"] = API_BASE_URL;
  axios.defaults.headers.common["X-API-KEY"] = API_KEY;
  axios.defaults.headers.common["Authorization"] = "Bearer " + token.token;

  const fetchApiData = async (url, options) => {
    const response = await fetch(url, options);
    return await response.json();
  };

  // Create DCQL Query for mDL
  events.emit(`presentation-${presentationId}`, {type: "message", message: "Creating DCQL Query for mDL."});
  const dcqlQueryUrl = `${API_BASE_URL}/oid4vp/dcql/queries`;
  const dcqlQueryOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      credentials: [
        {
          id: "mDL",
          format: "mso_mdoc",
          meta: {
            doctype_value: "org.iso.18013.5.1.mDL"
          },
          claims: [
            { namespace: "org.iso.18013.5.1", claim_name: "family_name" },
            { namespace: "org.iso.18013.5.1", claim_name: "given_name" },
            { namespace: "org.iso.18013.5.1", claim_name: "document_number" },
            { namespace: "org.iso.18013.5.1", claim_name: "issuing_country" },
            { namespace: "org.iso.18013.5.1", claim_name: "expiry_date" },
          ],
        }
      ]
    }),
  };
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting DCQL Query to: ${dcqlQueryUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: dcqlQueryOptions});
  const dcqlQueryData = await fetchApiData(dcqlQueryUrl, dcqlQueryOptions);
  const dcqlQueryId = dcqlQueryData.dcql_query_id;
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Created DCQL Query ID: ${dcqlQueryId}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: dcqlQueryData});

  // Create Presentation Request using the DCQL query
  const presentationRequestUrl = `${API_BASE_URL}/oid4vp/request`;
  const presentationRequestOptions = {
    method: "POST",
    headers: commonHeaders,
    body: JSON.stringify({
      dcql_query_id: dcqlQueryId,
      vp_formats: {
        mso_mdoc: {
          alg: ["ES256"]
        }
      },
    }),
  };
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generating Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Posting Presentation Request to: ${presentationRequestUrl}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Request options", data: presentationRequestOptions});
  const presentationRequestData = await fetchApiData(
    presentationRequestUrl,
    presentationRequestOptions
  );
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Generated Presentation Request.`});
  events.emit(`presentation-${presentationId}`, {type: "message", message: `Presentation Request URI: ${presentationRequestData?.request_uri}`});
  events.emit(`presentation-${presentationId}`, {type: "debug-message", message: "Response data", data: presentationRequestData});

  // Grab the relevant data and store it for later reference while waiting for the webhooks from ACA-Py
  let code = presentationRequestData.request_uri;
  presentationCache.set(dcqlQueryId, { dcqlQueryData, presentationRequestData, presentationId: presentationId });
  logger.trace(JSON.stringify(presentationRequestData, null, 2));

  // Generate a QRCode and return it to the browser (HTMX replaces a div with our current response)
  var qrcode = new QRCode({
    content: code,
    padding: 4,
    width: 256,
    height: 256,
    color: "#000000",
    background: "#ffffff",
    ecl: "M",
  });
  qrcode = qrcode.svg()
  qrcode = qrcode.substring(qrcode.indexOf('?>')+2,qrcode.length)
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(qrcode);
}

// ##     ## ######## ##     ## ##     ##
// ##     ##    ##    ###   ###  ##   ##
// ##     ##    ##    #### ####   ## ##
// #########    ##    ## ### ##    ###
// ##     ##    ##    ##     ##   ## ##
// ##     ##    ##    ##     ##  ##   ##
// ##     ##    ##    ##     ## ##     ##
// ######## ##     ## ######## ##    ## ########  ######
// ##       ##     ## ##       ###   ##    ##    ##    ##
// ##       ##     ## ##       ####  ##    ##    ##
// ######   ##     ## ######   ## ## ##    ##     ######
// ##        ##   ##  ##       ##  ####    ##          ##
// ##         ## ##   ##       ##   ###    ##    ##    ##
// ########    ###    ######## ##    ##    ##     ######

function handleEvents(event_type, req, res) {
  // Send headers indicating that this is an HTMX stream
  res.writeHead(200, {
    "Connection": "keep-alive",
    "Cache-Control": "no-cache",
    "Content-Type": "text/event-stream",
  });

  // Reset data
  logger.trace("HTMX Stream started!");
  res.write(`event: debug\ndata: \n\n`);
  res.write(`event: qrcode\ndata: \n\n`);
  let state = ""

  // When we receive an event
  events.on(`${event_type}-${req.params.id}`, (data) => {

    // Send messages verbatim
    if (data.type == "message") {
      res.write(`event: message\ndata: ${data.message}<br />\n\n`);
      return;
    }
    // Debug messages get special formatting
    if (data.type == "debug-message") {
      res.write(`event: message\ndata: <div style="text-indent: -1rem; padding-left: 1rem;">&gt; ${data.message}: ${JSON.stringify(data.data)}</div>\n\n`);
    }

    // Webhooks mean that ACA-Py sent us data regarding presentations or credential issuance
    if (data.type == "webhook") {

      // Log it for debugging
      logger.trace(JSON.stringify(data, null, 2));
      res.write(`event: message\ndata: <div style="text-indent: -1rem; padding-left: 1rem;">&gt; Webhook data: ${JSON.stringify(data.data)}</div>\n\n`);

      // Grab the state
      state = data?.data?.state;

      // Handle OID4VP webhooks
      if (data.path == "/webhook/topic/oid4vp/") {
        if (state == "request-retrieved")
          res.write(`event: status\ndata: <div style="text-align: center;">QRCode Scanned, awaiting presentation...</div>\n\n`);
        if (state == "presentation-invalid")
          res.write(`event: status\ndata: <div style="text-align: center;">Presentaion verification failed</div>\n\n`);
        if (state == "presentation-valid")
          res.write(`event: status\ndata: <div style="text-align: center;">Presentation Verified!</div>\n\n`);
      }

      // Handle OID4VCI webhooks
      if (data.path == "/webhook/topic/oid4vci/") {
        if (state == "issued") {
          res.write(`event: qrcode\ndata: Credential Issued!\n\n`);
          return;
        }
      }
    }
    res.write(`event: debug\ndata: ${JSON.stringify(data)}\n\n`);

    // For OID4VCI: when we receive a "qrcode" message, generate a code and send it to the browser
    if ("qrcode" in data) {
      var qrcode = new QRCode({
        content: data.qrcode,
        padding: 4,
        width: 256,
        height: 256,
        color: "#000000",
        background: "#ffffff",
        ecl: "M",
      });
      logger.debug(data.qrcode);
      res.write(`event: qrcode\ndata: ${qrcode.svg().replace(/\r?\n|\r/g, " ")}\n\n`);
    }
  });

  res.on("close", () => {
    res.end();
  });
}


// ########   #######  ##     ## ######## ########  ######
// ##     ## ##     ## ##     ##    ##    ##       ##    ##
// ##     ## ##     ## ##     ##    ##    ##       ##
// ########  ##     ## ##     ##    ##    ######    ######
// ##   ##   ##     ## ##     ##    ##    ##             ##
// ##    ##  ##     ## ##     ##    ##    ##       ##    ##
// ##     ##  #######   #######     ##    ########  ######
// Express.js Routes

// Render main app
app.get("/", (req, res) => {
  res.render("index", {"registrationId": uuidv4()});
});

const fetchApiData = async (url, options) => {
  const response = await fetch(url, options);
  return await response.json();
};

const token = await fetchApiData(
  `${API_BASE_URL}/multitenancy/wallet`,
  {
    method: "POST",
    headers: {
      accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(
      {
          "label": "Alice",
          "wallet_type": "askar",
      }
    )
  }
);

console.log("_______TOKEN________\n\n\n");
console.log(token);

const WALLET_ID = token.settings["wallet.id"];

// Configure the Issuer to point at Keycloak as the Authorization Server.
// Keycloak client/realm setup is handled via realm-import.json at startup.
async function initializeIssuerMetadata() {
  try {
    const commonHeaders = {
      accept: "application/json",
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token.token,
    };
    if (API_KEY) {
      commonHeaders["X-API-KEY"] = API_KEY;
    }

    // public_url is advertised to wallets in credential issuer metadata so they
    // can discover Keycloak's token endpoint. Use the ngrok URL when available
    // so wallets outside the Docker network can reach Keycloak.
    const keycloakPublicUrl = KEYCLOAK_NGROK_URL
      ? `${KEYCLOAK_NGROK_URL}/realms/${KEYCLOAK_REALM}`
      : `http://localhost:9001/realms/${KEYCLOAK_REALM}`;

    const payload = {
      authorization_servers: [
        {
          public_url: keycloakPublicUrl,
          private_url: `http://keycloak:8080/realms/${KEYCLOAK_REALM}`,
          auth_type: "keycloak",
          client_credentials: {
            client_id: KEYCLOAK_CLIENT_ID,
            client_secret: KEYCLOAK_CLIENT_SECRET,
            username: KEYCLOAK_USER,
            password: KEYCLOAK_PASSWORD,
          },
        },
      ],
    };

    const response = await axios.put(
      `${API_BASE_URL}/oid4vci/issuer/configuration`,
      payload,
      { headers: commonHeaders }
    );
    logger.info("Issuer metadata initialized:", response.data);
  } catch (err) {
    logger.error("Issuer metadata initialization failed:", err?.response?.data || err.message);
  }
}

// Create Signing DID. Note that this DID is used to sign both the credential and status list (required by IETF token status list spec)
let issuerDID = null;
async function initializeSigningDid() {
  try {
    const commonHeaders = {
      accept: "application/json",
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token.token,
    }
    const createDidUrl = `${API_BASE_URL}/did/jwk/create`;
    const createDidOptions = {
      method: "POST",
      headers: commonHeaders,
      body: JSON.stringify({
        key_type: "p256",
      }),
    };
    logger.info(`Posting Create DID Request to: ${createDidUrl}`);
    logger.info("Request options", createDidOptions);
    const didData = await fetchApiData(createDidUrl, createDidOptions);
    const { did } = didData;
    issuerDID = did;
    logger.info(`Created signing DID: ${issuerDID}`);
  } catch (err) {
    logger.error("Signing DID initialization failed:", err?.response?.data || err.message);
  }
}

// Import Certificate and private key.
let mdocKeyId = null;
async function initializeMdocSigningKey() {
  try {
    const commonHeaders = {
      accept: "application/json",
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token.token,
    }
    const createKeyUrl = `${API_BASE_URL}/mso-mdoc/signing-keys/import`;
    const createKeyOptions = {
      method: "POST",
      headers: commonHeaders,
      body: JSON.stringify({
          "certificate_pem": certificate_pem,
          "private_key_pem": private_key_pem,
          "doctype": "org.iso.18013.5.1.mDL",
          "label": "mDOC signing key",
      }),
    };
    logger.info(`Importing mDOC Signing Key Request to: ${createKeyUrl}`);
    logger.info("Request options", createKeyOptions);
    const keyData = await fetchApiData(createKeyUrl, createKeyOptions);
    mdocKeyId = keyData.id;
    logger.info(`Imported mDOC signing key with ID: ${mdocKeyId}`);

    // Register the certificate as a trust anchor
    const trustAnchorUrl = `${API_BASE_URL}/mso-mdoc/trust-anchors`;
    const trustAnchorOptions = {
      method: "POST",
      headers: commonHeaders,
      body: JSON.stringify({
        certificate_pem: certificate_pem,
      }),
    };
    logger.info(`Registering mDOC trust anchor to: ${trustAnchorUrl}`);
    const trustAnchorData = await fetchApiData(trustAnchorUrl, trustAnchorOptions);
    logger.info(`Registered mDOC trust anchor:`, trustAnchorData);
  } catch (err) {
    logger.error("mDOC signing key initialization failed:", err?.response?.data || err.message);
  }
}

await initializeIssuerMetadata();
await initializeSigningDid();
await initializeMdocSigningKey();


// Credential Info route
app.get("/credential-info", async (req, res, next) => {
  try {
    const recordsUrl = `${API_BASE_URL}/oid4vci/exchange/records`;
    const commonHeaders = {
      accept: "application/json",
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token.token,
    };
    if (API_KEY) {
      commonHeaders["X-API-KEY"] = API_KEY;
    }

    const response = await fetch(recordsUrl, {
      method: "GET",
      headers: commonHeaders
    });
    
    if (response.ok) {
      const records = await response.json();
      res.render("credential-info", { "page": "credential-info", records: JSON.stringify(records, null, 2) });
    } else {
      const respData = await response.text();
      res.status(response.status).send(`<div class="w3-panel w3-pale-red w3-border"><p>Failed to fetch records: ${respData}</p></div>`);
    }
  } catch (err) {
    next(err);
  }
});

// Update Status routes
app.get("/update-status", (req, res) => {
  res.render("update-status-form", {"page": "update-status"});
});
app.get("/update-status/select", (req, res) => {
  res.render(`update-status-fields`, {"page": "update-status"});
});
app.post("/update-status", async (req, res, next) => {
  try {
    const credType = req.body["credential-type"];
    const credId = req.body["credential-id"];
    
    let defId = "";
    if (credType === "jwt") {
      defId = jwtStatusListID;
    } else if (credType === "sdjwt") {
      defId = sdJwtStatusListID;
    } else {
      return res.status(400).send("Invalid credential type for status update.");
    }
    
    if (!defId) {
      return res.status(400).send("Status list for this credential type has not been created yet.");
    }

    const updateUrl = `${API_BASE_URL}/status-list/defs/${defId}/creds/${credId}`;
    const commonHeaders = {
      accept: "application/json",
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token.token,
    };
    if (API_KEY) {
      commonHeaders["X-API-KEY"] = API_KEY;
    }

    const response = await fetch(updateUrl, {
      method: "PATCH",
      headers: commonHeaders,
      body: JSON.stringify({ status: "1" })
    });
    
    const respData = await response.text();
    
    if (respData.includes("StatusListCred record not found")) {
      res.send(`<div class="w3-panel w3-pale-red w3-border"><p>${respData}</p></div>`);
    } else if (response.ok) {
      res.send(`<div class="w3-panel w3-pale-green w3-border"><p>Status successfully updated for Credential Exchange ID: ${credId}</p></div>`);
    } else {
      res.status(response.status).send(`<div class="w3-panel w3-pale-red w3-border"><p>Failed to update status: ${respData}</p></div>`);
    }
  } catch (err) {
    next(err);
  }
});

// Render Credential Issuance form
app.get("/issue", (req, res) => {
  res.render("issue-form", {"page": "register", "registrationId": uuidv4()});
});
app.get("/issue/select", (req, res) => {
  console.log(req.query);
  res.render(`issue/${req.query["credential-type"]}`, {"page": "register", "registrationId": uuidv4()});
});

app.post("/issue", (req, res, next) => {
  // Begin Credential issuance flow
  //events.on(`${event_type}-${req.params.id}`, (data) => {
    console.log(req.body);
    switch(req.body["credential-type"]) {
      case "jwt":
        issue_jwt_credential(req, res).catch(next);
        break;
      case "sdjwt":
        issue_sdjwt_credential(req, res).catch(next);
        break;
      case "mdoc":
        issue_mdoc_credential(req, res).catch(next);
      break;
      default:
        res.status(400).send("");
    }
  });

  // Event Stream for Issuance page
  app.get("/stream/issue/:id", (req, res) => {
    handleEvents("issuance", req, res);
  });

  app.get("/present/select/:id", (req, res) => {
    console.log(req.query);
    res.render(`present/${req.query["credential-type"]}`, {"page": "register", "presentationId": req.params.id});
  });

  // Render Presentation Exchange form
  app.get("/present", (req, res) => {
    res.render("presentation", {"page": "present", "presentationId": uuidv4()});
  });

  app.get("/present/create/:id", (req, res, next) => {
    // Begin Presentation Exchange flow

    switch(req.query["credential-type"]) {
      case "jwt":
        create_jwt_vc_presentation(req, res).catch(next);
        break;
      case "multi":
        create_jwt_vc_presentation_multi(req, res).catch(next);
        break;
      case "sdjwt":
        create_sd_jwt_presentation(req, res).catch(next);
        break;
      case "mdoc":
        create_mdoc_presentation(req, res).catch(next);
        break;
      default:
        res.status(400).send("");
    }
  });

  // Event Stream for Presentation page
  app.get("/stream/present/:id", (req, res) => {
    handleEvents("presentation", req, res);
  });

  // ##      ## ######## ########  ##     ##  #######   #######  ##    ##  ######
  // ##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##   ##  ##    ##
  // ##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##  ##   ##
  // ##  ##  ## ######   ########  ######### ##     ## ##     ## #####     ######
  // ##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##  ##         ##
  // ##  ##  ## ##       ##     ## ##     ## ##     ## ##     ## ##   ##  ##    ##
  //  ###  ###  ######## ########  ##     ##  #######   #######  ##    ##  ######
  // ACA-Py sends webhook events when something happens within ACA-Py (such as
    // when a credential is issued or a presentation has been varified). These
  // webhooks showcase the current state of ACA-Py flows and can be acted upon to
  // give users up-to-date and realtime info.

    app.post("/webhook/*", (req, res, next) => {
      logger.trace("Webhook received");
      logger.trace(req.path);
      logger.trace(JSON.stringify(req.body));
      if (req.path == "/webhook/topic/oid4vci/") {
        // If there's no exchange ID, we can't look up the request
        if (!req.body.exchange_id) return;

        // Check to see if this belongs to us
        let exchange = exchangeCache.get(req.body.exchange_id);
        if (!exchange) return;

        // Dispatch event
        events.emit(`issuance-${exchange.registrationId}`, {type: "webhook", path: req.path, data: req.body});
      }
      if (req.path == "/webhook/topic/oid4vp/") {
        // Look up by pres_def_id or dcql_query_id
        const lookupId = req.body.pres_def_id || req.body.dcql_query_id;
        if (!lookupId) return;

        // Check to see if this belongs to us
        let exchange = presentationCache.get(lookupId);
        if (!exchange) return;

        // Dispatch event
        events.emit(`presentation-${exchange.presentationId}`, {type: "webhook", path: req.path, data: req.body});
      }
    });

  app.listen(3000, () => {
    console.log("App listening on port 3000");
  });
