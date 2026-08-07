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
import type {
  AuthenticationResponseJSON,
  AuthenticatorTransportFuture,
  RegistrationResponseJSON,
} from "@simplewebauthn/types";
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
import session from "express-session";
import fs from "fs";
import http from "http";
import https from "https";
import logger from "./logger";
import { CeremonyStore } from "./ceremony-store";
import { DEFAULT_EXPECTED_ORIGINS, DEFAULT_RP_ID, RP_NAME, TIMEOUT } from "./constants";
import csrf from 'lusca';
import rateLimit from 'express-rate-limit';
dotenv.config();

type AuthenticatorDevice = {
  credentialPublicKey: string;
  credentialID: string;
  counter: number;
  transports: AuthenticatorTransportFuture[];
};

declare module "express-session" {
  interface SessionData {
    /** Set only by the application's server-side authentication middleware. */
    authenticatedUserId?: string;
  }
}

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10000, // Limit each IP to 10000 requests per windowMs
  message: 'Too many requests from this IP, please try again after 15 minutes',
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

const { ENABLE_CONFORMANCE, ENABLE_HTTPS } = process.env;

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
export const rpID = process.env.RP_ID ? (process.env.RP_ID) : DEFAULT_RP_ID;
// This value is set at the bottom of page as part of server initialization (the empty string is
// to appease TypeScript until we determine the expected origin based on whether or not HTTPS
// support is enabled)
export const expectedOrigin = process.env.EXPECTED_ORIGINS
  ? process.env.EXPECTED_ORIGINS
  : DEFAULT_EXPECTED_ORIGINS; // Change expectedOrigin according to environment

const sessionSecret = process.env.SESSION_SECRET;
if (!sessionSecret) {
  throw new Error("SESSION_SECRET must be configured");
}

const app = express();
const ceremonies = new CeremonyStore(TIMEOUT);
const devicesByUser = new Map<string, AuthenticatorDevice[]>();

app.use(cors());
app.use(express.static("./public/"));
app.use(express.json());
app.use(session({
  cookie: { httpOnly: true, sameSite: "lax", secure: ENABLE_HTTPS === "true" },
  resave: false,
  saveUninitialized: false,
  secret: sessionSecret,
}));
app.use(csrf());
app.use(apiLimiter);

function getAuthenticatedUserId(req: express.Request, res: express.Response): string | undefined {
  const userId = req.session.authenticatedUserId;
  if (typeof userId !== "string" || userId.trim() === "") {
    res.status(401).json({ error: "An authenticated user session is required" });
    return undefined;
  }
  return userId;
}

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
  const userId = getAuthenticatedUserId(req, res);
  if (!userId) {
    return;
  }
  try {
    const devices = devicesByUser.get(userId) || [];
    const opts: GenerateRegistrationOptionsOpts = {
      rpName: process.env.RP_NAME ? process.env.RP_NAME : RP_NAME,
      rpID: rpID,
      userID: userId,
      userName: userId,
      timeout: TIMEOUT,
      attestationType: "none",
      /**
       * Passing in a user's list of already-registered authenticator IDs here prevents users from
       * registering the same device multiple times. The authenticator will simply throw an error in
       * the browser if it's asked to perform registration when one of these ID's already resides
       * on it.
       */
      excludeCredentials: devices.map((device) => ({
        id: Buffer.from(device.credentialID, "base64"),
        transports: device.transports,
        type: "public-key" as const,
      })),
      authenticatorSelection: {
        residentKey: "discouraged",
      },
      /**
       * Support the two most common algorithms: ES256, and RS256
       */
      supportedAlgorithmIDs: [-7, -257],
    };

    const options = await generateRegistrationOptions(opts);
    const ceremonyId = ceremonies.create("registration", userId, options.challenge);
    res.json({ ...options, ceremonyId });
  } catch (error) {
    logger.error("Error generating registration options", error);
    return res
      .status(500)
      .json({ error: "Failed to generate registration options" });
  }
});
app.post('/verify-registration', async (req, res) => {
  logger.info('verify-registration-called');
  const userId = getAuthenticatedUserId(req, res);
  if (!userId) {
    return;
  }

  const { ceremonyId, response } = req.body as {
    ceremonyId?: unknown;
    response?: RegistrationResponseJSON;
  };
  if (typeof ceremonyId !== "string" || !response) {
    return res.status(400).json({ error: "A ceremony ID and registration response are required" });
  }

  const ceremony = ceremonies.consume(ceremonyId, "registration");
  if (!ceremony || ceremony.userId !== userId) {
    return res.status(400).json({ error: "Registration ceremony is invalid or has expired" });
  }

  try {
    const opts: VerifyRegistrationResponseOpts = {
      response,
      expectedChallenge: ceremony.challenge,
      expectedOrigin,
      requireUserVerification: true,
    };

    const verification: VerifiedRegistrationResponse = await verifyRegistrationResponse(opts);
    
    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      const { credentialPublicKey, credentialID, counter } = registrationInfo;
      const newDevice: AuthenticatorDevice = {
        credentialPublicKey: Buffer.from(credentialPublicKey).toString('base64'),
        credentialID: Buffer.from(credentialID).toString('base64'),
        counter,
        transports: response.response.transports || [],
      };
      const devices = devicesByUser.get(userId) || [];
      if (!devices.some((device) => device.credentialID === newDevice.credentialID)) {
        devices.push(newDevice);
        devicesByUser.set(userId, devices);
      }
    }
    res.status(200).json({ verified });
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
  const userId = getAuthenticatedUserId(req, res);
  if (!userId) {
    return;
  }
  try {
    if (!TIMEOUT || typeof TIMEOUT !== 'number') {
      return res.status(400).json({ error: 'Invalid timeout value' });
    }
    const devices = devicesByUser.get(userId) || [];
    if (devices.length === 0) {
      return res.status(404).json({ error: "No registered authenticator is available for this user" });
    }
    const opts: GenerateAuthenticationOptionsOpts = {
      timeout: TIMEOUT,
      allowCredentials: devices.map((device) => ({
        id: Buffer.from(device.credentialID, "base64"),
        transports: device.transports,
        type: "public-key" as const,
      })),
      userVerification: 'required',
      rpID,
    };
    const options = await generateAuthenticationOptions(opts);
    const ceremonyId = ceremonies.create("authentication", userId, options.challenge);
    return res.status(200).json({ ...options, ceremonyId });
  } catch (error) {
    const _error = error as Error;
    logger.error('Error generating authentication options', _error);
    return res.status(500).json({ error: _error.message });
  }
});


app.post("/verify-authentication", async (req, res) => {
  logger.info("verify-authentication-called");
  const userId = getAuthenticatedUserId(req, res);
  if (!userId) {
    return;
  }
  const { ceremonyId, response } = req.body as {
    ceremonyId?: unknown;
    response?: AuthenticationResponseJSON;
  };
  if (typeof ceremonyId !== "string" || !response) {
    return res.status(400).json({ error: "A ceremony ID and authentication response are required" });
  }

  const ceremony = ceremonies.consume(ceremonyId, "authentication");
  if (!ceremony || ceremony.userId !== userId) {
    return res.status(400).json({ error: "Authentication ceremony is invalid or has expired" });
  }

  const credentialID = Buffer.from(base64url.toBuffer(response.rawId)).toString("base64");
  const existingDevice = (devicesByUser.get(userId) || []).find(
    (device) => device.credentialID === credentialID,
  );
  if (!existingDevice) {
    return res.status(400).json({ error: "Authenticator is not registered for this user" });
  }

  const dbAuthenticator = {
    counter: existingDevice.counter,
    credentialID: new Uint8Array(Buffer.from(existingDevice.credentialID, "base64")),
    credentialPublicKey: new Uint8Array(Buffer.from(existingDevice.credentialPublicKey, "base64")),
    transports: existingDevice.transports,
  };

  let verification: VerifiedAuthenticationResponse;
  try {
    const opts: VerifyAuthenticationResponseOpts = {
      response,
      expectedChallenge: ceremony.challenge,
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
    existingDevice.counter = authenticationInfo.newCounter;
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
