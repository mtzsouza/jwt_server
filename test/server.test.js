// Imports
import { expect } from 'chai';
import supertest from 'supertest';
import app from '../jwks_server.js';

// Global
const request = supertest(app);

describe("JWT Server Tests", () => {
  it("should hit the POST /auth endpoint and should return a successful response", async () => {
    const response = await request.post("/auth");
    expect(response.status).to.equal(200);
  });

  it("should hit the GET /.well-known/jwks.json endpoint and should return a valid JWKS array", async () => {
    const response = await request.get("/.well-known/jwks.json");
    expect(response.status).to.equal(200);
    expect(response.body).to.have.property("keys").that.is.an("array"); // There should be an array of keys

    const key = response.body.keys[0]; // Validating first key
    expect(key).to.have.property("kid").that.is.a("string"); // kid must be a string
    expect(key).to.have.property("kty", "RSA"); // kty must be RSA
    expect(key).to.have.property("alg", "RS256"); // alg must be RS256
    expect(key).to.have.property("use", "sig"); // should be for signing
    expect(key).to.have.property("n").that.is.a("string"); // modulus must be string
    expect(key).to.have.property("e", "AQAB"); // exponent has to be AQAB
  });
});
