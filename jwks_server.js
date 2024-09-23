// Imports
import express from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

// Global
const app = express();
const SERVER_PORT = 8080;
let keyStore = [];

app.use(express.json()); // Need this so we can read JSON from incoming requests

// Makes a new RSA key pair and sets it to expire in an hour
function createRSAKey() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  const keyID = crypto.randomBytes(16).toString("hex"); // Random key ID for identification
  const expirationTime = Math.floor(Date.now() / 1000) + 3600; // Expires in 1 hour from now

  return { keyID, publicKey, privateKey, expirationTime };
}

// Creates an RSA key pair that already expired
const createExpiredRSAKey = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

  const keyID = crypto.randomBytes(16).toString("hex");
  const expiredTime = Math.floor(Date.now() / 1000) - 3600;

  return { keyID, publicKey, privateKey, expiredTime };
};

let activeKey = createRSAKey(); // Keeps track of the current active key

// Turns public key into its modulus and exponent
function extractModulus(publicKeyPem) {
  const publicKeyObj = crypto.createPublicKey({
    key: publicKeyPem,
    format: "pem",
  });

  const modulusBuffer = publicKeyObj.export({ type: "pkcs1", format: "der" });
  const modulus = modulusBuffer.toString("base64");
  const exponent = "AQAB"; // This is pretty standard for RSA

  return { modulus, exponent };
}

// GET endpoint that returns all keys
app.get("/.well-known/jwks.json", (req, res) => {
  console.log("Current Key Store:", JSON.stringify(keyStore, null, 2));
  if (keyStore.length === 0) {
    keyStore.push({
      kid: activeKey.keyID,
      kty: "RSA",
      use: "sig",
      alg: "RS256",
      n: Buffer.from(activeKey.publicKey, "utf-8").toString("base64"),
      e: "AQAB",
    });
  }

  res.json({ keys: keyStore });
});

// POST endpoint
app.post("/auth", (req, res) => {
  const expired = req.query.expired === "true";
  let jwtToken;

  const { modulus, exponent } = extractModulus(activeKey.publicKey);
  const newJwk = {
    kty: "RSA",
    use: "sig",
    kid: activeKey.keyID,
    alg: "RS256",
    n: modulus,
    e: exponent,
  };

  // Ensure the key is in the keyStore
  if (!keyStore.some(key => key.kid === activeKey.keyID)) {
    keyStore.push(newJwk);
  }

  if (expired) {
    activeKey = createExpiredRSAKey(); // Generates an expired key if 'expired' is true
    jwtToken = jwt.sign(
      {
        username: req.body.username || "Silly User",
      },
      activeKey.privateKey,
      {
        algorithm: "RS256",
        expiresIn: "-1h", // Token expired 1 hour ago
        keyid: activeKey.keyID,
      }
    );
  } else {
    jwtToken = jwt.sign(
      {
        username: req.body.username || "Dummy User",
      },
      activeKey.privateKey,
      {
        algorithm: "RS256",
        expiresIn: "1h", // Token is good for 1 hour
        keyid: activeKey.keyID,
      }
    );
  }

  res.set("Content-Type", "text/plain");
  res.removeHeader("Connection");
  res.removeHeader("X-Powered-By");
  res.status(200).send(jwtToken); // Send the generated JWT back to the client
});

// Starting the server
app.listen(SERVER_PORT, () =>
  console.log(`API running on http://localhost:${SERVER_PORT}`)
);

export default app; // Export the app for testing
