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
} from "@simplewebauthn/server";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";

import base64url from "base64url";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import fs from "fs";
import http from "http";
import https from "https";
import { isoUint8Array } from "@simplewebauthn/server/helpers";
import logger from "./logger";
import { DEFAULT_EXPECTED_ORIGINS, DEFAULT_RP_ID, RP_NAME, TIMEOUT } from "./constants";
import csrf from 'lusca';
import rateLimit from 'express-rate-limit';
dotenv.config();

type AuthenticatorDevice = {
  credentialPublicKey: string;
  credentialID: string;
  counter: number;
  transports: string[];
};

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10000, // Limit each IP to 10000 requests per windowMs
  message: 'Too many requests from this IP, please try again after 15 minutes',
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

dotenv.config();

const app = express();

const { ENABLE_CONFORMANCE, ENABLE_HTTPS } = process.env;
app.use(cors());
app.use(express.static("./public/"));
app.use(express.json());
app.use(csrf());
app.use(apiLimiter);

/**
 * If the words "metadata statements" mean anything to you, you'll want to enable this route. It
 * contains an example of a more complex deployment of SimpleWebAuthn with support enabled for the
 * FIDO Metadata Service. This enables greater control over the types of authenticators that can
 * interact with the Rely Party (a.k.a. "RP", a.k.a. "this server").
 */
if (ENABLE_CONFORMANCE === "true") {
  import("./fido-conformance").then(
    ({ fidoRouteSuffix, fidoConformanceRouter }) => {
      app.use(fidoRouteSuffix, fidoConformanceRouter);
    }
  );
}

/**
 * RP ID represents the "scope" of websites on which a authenticator should be usable. The Origin
 * represents the expected URL from which registration or authentication occurs.
 */
const rpID = process.env.RP_ID ? (process.env.RP_ID) : DEFAULT_RP_ID;
// This value is set at the bottom of page as part of server initialization (the empty string is
// to appease TypeScript until we determine the expected origin based on whether or not HTTPS
// support is enabled)
const expectedOrigin = process.env.EXPECTED_ORIGINS
  ? process.env.EXPECTED_ORIGINS
  : DEFAULT_EXPECTED_ORIGINS; // Change expectedOrigin according to environment

/**
 * 2FA and Passwordless WebAuthn flows expect you to be able to uniquely identify the user that
 * performs registration or authentication. The user ID you specify here should be your internal,
 * _unique_ ID for that user (uuid, etc...). Avoid using identifying information here, like email
 * addresses, as it may be stored within the authenticator.
 *
 * Here, the example server assumes the following user has completed login:
 */
/**
 * Registration (a.k.a. "Registration")
 */
app.get("/generate-registration-options", async (req, res) => {
  logger.info("generate-registration-options-called");
  let userName = req.query.userName;

  if (typeof userName !== "string" || userName.trim() === "") {
    return res
      .status(400)
      .json({ error: "Invalid username: must be a non-empty string" });
  }
  try {
    const opts: GenerateRegistrationOptionsOpts = {
      rpName: process.env.RP_NAME ? process.env.RP_NAME : RP_NAME,
      rpID: rpID,
      userID: userName,
      userName: userName,
      timeout: TIMEOUT,
      attestationType: "none",
      /**
       * Passing in a user's list of already-registered authenticator IDs here prevents users from
       * registering the same device multiple times. The authenticator will simply throw an error in
       * the browser if it's asked to perform registration when one of these ID's already resides
       * on it.
       */
      excludeCredentials: [],
      authenticatorSelection: {
        residentKey: "discouraged",
      },
      /**
       * Support the two most common algorithms: ES256, and RS256
       */
      supportedAlgorithmIDs: [-7, -257],
    };

    const options = await generateRegistrationOptions(opts);
    res.send(options);
  } catch (error) {
    logger.error("Error generating registration options", error);
    return res
      .status(500)
      .json({ error: "Failed to generate registration options" });
  }
});
app.post('/verify-registration', async (req, res) => {
  logger.info('verify-registration-called');

  const { challangeId, ...body } = req.body;  //TODO: Correct the name `challangeId`

  if (!challangeId || typeof challangeId !== 'string') {
    return res.status(400).json({ error: 'Invalid challenge ID' });
  }

  try {
    const opts: VerifyRegistrationResponseOpts = {
      response: body,
      expectedChallenge: challangeId,
      expectedOrigin,
      requireUserVerification: true,
    };

    const verification: VerifiedRegistrationResponse = await verifyRegistrationResponse(opts);
    
    const { verified, registrationInfo } = verification;

    let newDevice: AuthenticatorDevice = {
      credentialPublicKey: "",
      credentialID: "",
      counter: 0,
      transports: []
    };
    if (verified && registrationInfo) {
      const { credentialPublicKey, credentialID, counter } = registrationInfo;
      newDevice = {
        credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64'),
        credentialID: Buffer.from(credentialID).toString('base64'),
        counter,
        transports: body.response.transports || [],
      };
    }
    res.status(200).json({ verified, newDevice });
  } catch (error) {
    // **Error Handling**: Catch and log any errors during verification.
    const _error = error as Error;
    logger.error('Error verifying registration', _error);
    return res.status(400).json({ error: _error.message });
  }
});


/**
 * Login (a.k.a. "Authentication")
 */
app.post('/generate-authentication-options', async (req, res) => {
  logger.info('generate-authentication-options-called');
  try {
    if (!TIMEOUT || typeof TIMEOUT !== 'number') {
      return res.status(400).json({ error: 'Invalid timeout value' });
    }
    const opts: GenerateAuthenticationOptionsOpts = {
      timeout: TIMEOUT,
      allowCredentials: [],
      userVerification: 'required',
      rpID,
    };
    const options = await generateAuthenticationOptions(opts);
    return res.status(200).json(options);
  } catch (error) {
    const _error = error as Error;
    logger.error('Error generating authentication options', _error);
    return res.status(500).json({ error: _error.message });
  }
});


app.post("/verify-authentication", async (req, res) => {
  logger.info("verify-authentication-called");
  const { challangeId, ...body } = JSON.parse(
    req?.body?.verifyAuthenticationDetails
  );
  const expectedChallenge = challangeId;

  let dbAuthenticator = {
    credentialPublicKey: new Uint8Array(),
    credentialID: new Uint8Array(),
    counter: 0,
    transports: [],
  };

  req?.body?.devices.map((cred: any) => {
    const bodyCredIDBuffer = base64url.toBuffer(body.rawId);
    const credId = new Uint8Array(Buffer.from(cred.credentialId, "base64"));
    const result = isoUint8Array.areEqual(credId, bodyCredIDBuffer);
    const pubKey = new Uint8Array(
      Buffer.from(cred?.devices?.credentialPublicKey, "base64")
    );
    if (result) {
      dbAuthenticator = {
        counter: cred?.devices?.counter,
        transports: cred?.devices?.transports,
        credentialID: credId,
        credentialPublicKey: pubKey,
      };
    }
  });

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
    dbAuthenticator.counter = authenticationInfo.newCounter;
  }

  res.send({ verified });
});

if (ENABLE_HTTPS === 'true') {
  const host = "0.0.0.0";
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
      app
    )
    .listen(port, host, () => {
      console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
    });
} else {
  const host = "0.0.0.0";
  const port = 8000;
  const expectedOrigin = `http://localhost:${port}`;

  http.createServer(app).listen(port, host, () => {
    console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
  });
}
