/* eslint-disable @typescript-eslint/no-var-requires */
/**
 * An example Express server showing off a simple integration of @simplewebauthn/server.
 *
 * The webpages served from ./public use @simplewebauthn/browser.
 */

import type {
  GenerateAuthenticationOptionsOpts,
  GenerateRegistrationOptionsOpts,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
  VerifyAuthenticationResponseOpts,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';

import { LoggedInUser } from './example-server';
import base64url from 'base64url';
import cors from 'cors';
import dotenv from 'dotenv';
import express from 'express';
import fs from 'fs';
import http from 'http';
import https from 'https';
import { isoUint8Array } from '@simplewebauthn/server/helpers';
import memoryStore from 'memorystore';
import session from 'express-session';

dotenv.config();

const app = express();
const MemoryStore = memoryStore(session);

const { ENABLE_CONFORMANCE, ENABLE_HTTPS, RP_ID = 'localhost' } = process.env; // Change RP_ID according to environment
app.use(cors());
app.use(express.static('./public/'));
app.use(express.json());
app.use(
  session({
    secret: 'secret123',
    saveUninitialized: true,
    resave: false,
    cookie: {
      maxAge: 86400000,
      httpOnly: true, // Ensure to not expose session cookies to clientside scripts
    },
    store: new MemoryStore({
      //checkPeriod: 86_400_000, // prune expired entries every 24h
    }),
  }),
);

/**
 * If the words "metadata statements" mean anything to you, you'll want to enable this route. It
 * contains an example of a more complex deployment of SimpleWebAuthn with support enabled for the
 * FIDO Metadata Service. This enables greater control over the types of authenticators that can
 * interact with the Rely Party (a.k.a. "RP", a.k.a. "this server").
 */
if (ENABLE_CONFORMANCE === 'true') {
  import('./fido-conformance').then(({ fidoRouteSuffix, fidoConformanceRouter }) => {
    app.use(fidoRouteSuffix, fidoConformanceRouter);
  });
}

/**
 * RP ID represents the "scope" of websites on which a authenticator should be usable. The Origin
 * represents the expected URL from which registration or authentication occurs.
 */
export const rpID = RP_ID;
// This value is set at the bottom of page as part of server initialization (the empty string is
// to appease TypeScript until we determine the expected origin based on whether or not HTTPS
// support is enabled)
export const expectedOrigin = 'http://localhost:3000'; //// Change expectedOrigin according to environment

/**
 * 2FA and Passwordless WebAuthn flows expect you to be able to uniquely identify the user that
 * performs registration or authentication. The user ID you specify here should be your internal,
 * _unique_ ID for that user (uuid, etc...). Avoid using identifying information here, like email
 * addresses, as it may be stored within the authenticator.
 *
 * Here, the example server assumes the following user has completed login:
 */
const loggedInUserId = 'internalUserId';

const inMemoryUserDeviceDB: { [loggedInUserId: string]: LoggedInUser } = {
  [loggedInUserId]: {
    id: loggedInUserId,
    username: `CREDEBL@${rpID}`,
    devices: [],
  },
};

/**
 * Registration (a.k.a. "Registration")
 */
app.get('/generate-registration-options', async (req, res) => {
  const user = inMemoryUserDeviceDB[loggedInUserId];
  let userName = req.query.userName;
  if (typeof userName !== 'string') {
    throw new Error("Username is not string")
  }
  let {
    /**
     * The username can be a human-readable name, email, etc... as it is intended only for display.
     */
    devices,
  } = user;
  devices = [];
  const opts: GenerateRegistrationOptionsOpts = {
    rpName: 'SimpleWebAuthn Example',
    rpID,
    userID: userName,
    userName: userName,
    timeout: 60000,
    attestationType: 'none',
    /**
     * Passing in a user's list of already-registered authenticator IDs here prevents users from
     * registering the same device multiple times. The authenticator will simply throw an error in
     * the browser if it's asked to perform registration when one of these ID's already resides
     * on it.
     */
    excludeCredentials: devices.map(dev => ({
      id: dev.credentialID,
      type: 'public-key',
      transports: dev.transports,
    })),
    authenticatorSelection: {
      residentKey: 'discouraged',
    },
    /**
     * Support the two most common algorithms: ES256, and RS256
     */
    supportedAlgorithmIDs: [-7, -257],
  };
 
  const options = await generateRegistrationOptions(opts);
   
  /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify an authenticator response.
   */
  req.session.currentChallenge = (await options).challenge;

  res.send(options);
});

app.post('/verify-registration', async (req, res) => {
  const { challangeId, ...rest } = req?.body;
  const body = rest;
  const user = inMemoryUserDeviceDB[loggedInUserId];
  const expectedChallenge = challangeId;
  let verification: VerifiedRegistrationResponse;
  try {
    const opts: VerifyRegistrationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      requireUserVerification: true,
    };
    verification = await verifyRegistrationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }
  const { verified, registrationInfo } = verification;
  let newDevice: any = {};
  if (verified && registrationInfo) {
    const { credentialPublicKey, credentialID, counter } = registrationInfo;

    const existingDevice = user.devices.find(device =>
      isoUint8Array.areEqual(device.credentialID, credentialID),
    );

    if (!existingDevice) {
      /**
       * Add the returned device to the user's list of devices
       */
      newDevice = {
        credentialPublicKey,
        credentialID,
        counter,
        transports: body.response.transports,
      };
      user.devices.push(newDevice);
    }
  }

  req.session.currentChallenge = undefined;
  const pubKey = Buffer.from(newDevice.credentialPublicKey).toString('base64');
  const credID = Buffer.from(newDevice.credentialID).toString('base64');
  newDevice = {
    credentialPublicKey: pubKey,
    credentialID: credID,
    counter: newDevice.counter,
    transports: body.response.transports,
  };

  res.send({ verified, newDevice });
});

/**
 * Login (a.k.a. "Authentication")
 */
app.post('/generate-authentication-options', async (req, res) => {
 
  let allowCredential = [];
  for (const credentialId of req.body) {

    let credentialID = new Uint8Array(Buffer.from(credentialId as any, 'base64'));;
    allowCredential.push({
      id: credentialID,
      type: 'public-key',
      transports: [],
    })
  }

  const opts: GenerateAuthenticationOptionsOpts = {
    timeout: 60000,
    allowCredentials: [],
    userVerification: 'required',
    rpID,
  };
  const options = await generateAuthenticationOptions(opts);
  /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify an authenticator response.
   */
  req.session.currentChallenge = (await options).challenge;

  res.send(options);
});

app.post('/verify-authentication', async (req, res) => {
  const { challangeId, ...rest } = JSON.parse(req?.body?.verifyAuthenticationDetails);
  const body = rest;
  const expectedChallenge = challangeId;

  let dbAuthenticator = {
    credentialPublicKey: new Uint8Array(),
    credentialID: new Uint8Array(),
    counter: 0,
    transports: [],
  };
  req?.body?.devices.map((cred: any) => {
    const bodyCredIDBuffer = base64url.toBuffer(body.rawId);
    const credId = new Uint8Array(Buffer.from(cred.credentialId, 'base64'));
    const result = isoUint8Array.areEqual(credId, bodyCredIDBuffer);
    const pubKey = new Uint8Array(Buffer.from(cred?.devices?.credentialPublicKey, 'base64'),
    );
    if (result) {
      dbAuthenticator = {
        counter: cred?.devices?.counter,
        transports: cred?.devices?.transports,
        credentialID: credId,
        credentialPublicKey: pubKey
      }
    }

  })
 
  let verification: VerifiedAuthenticationResponse;
  try {
    const opts: VerifyAuthenticationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: dbAuthenticator,
      requireUserVerification: true,
    };
 
    verification = await verifyAuthenticationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }
  const { verified, authenticationInfo } = verification;

  if (verified) {
    // Update the authenticator's counter in the DB to the newest count in the authentication
    dbAuthenticator.counter = authenticationInfo.newCounter;
  }

  req.session.currentChallenge = undefined;

  res.send({ verified });
});

if (ENABLE_HTTPS) {
  const host = '0.0.0.0';
  const port = 443;
  const expectedOrigin = `https://${rpID}`;

  https
    .createServer(
      {
        /**
         * See the README on how to generate this SSL cert and key pair using mkcert
         */
        key: fs.readFileSync(`./${rpID}.key`),
        cert: fs.readFileSync(`./${rpID}.crt`),
      },
      app,
    )
    .listen(port, host, () => {
      console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
    });
} else {
  const host = '0.0.0.0';
  const port = 8000;
  const expectedOrigin = `http://localhost:${port}`;

  http.createServer(app).listen(port, host, () => {
    console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
  });
}
