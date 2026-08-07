const assert = require("node:assert/strict");
const test = require("node:test");

const { CeremonyStore } = require("../dist/ceremony-store");

test("binds a ceremony to server-side state and consumes it once", () => {
  let now = 100;
  const store = new CeremonyStore(1000, () => now);
  const id = store.create("registration", "user-1", "challenge-1");

  assert.deepEqual(store.consume(id, "registration"), {
    challenge: "challenge-1",
    expiresAt: 1100,
    type: "registration",
    userId: "user-1",
  });
  assert.equal(store.consume(id, "registration"), undefined);
});

test("rejects an expired ceremony and a ceremony of the wrong type", () => {
  let now = 100;
  const store = new CeremonyStore(100, () => now);
  const registrationId = store.create("registration", "user-1", "challenge-1");
  const authenticationId = store.create("authentication", "user-1", "challenge-2");

  assert.equal(store.consume(registrationId, "authentication"), undefined);
  now = 200;
  assert.equal(store.consume(authenticationId, "authentication"), undefined);
});
