import assert from "node:assert/strict";
import test from "node:test";
import { findIoc, validateIoc } from "./iocs.js";
import { matchInventory } from "./inventoryMatch.js";

test("IOC matching is exact for addresses and bounded for domains", () => {
  const iocs = [
    { kind: "ip", value: "203.0.113.10" },
    { kind: "domain", value: "evil.example" },
    { kind: "hash", value: "a".repeat(64) },
    { kind: "other", value: "1" }
  ];
  assert.equal(findIoc(iocs, { message: "hello 203.0.113.10 there", sourceIp: null })?.kind, "ip");
  assert.equal(findIoc(iocs, { message: "hello 203.0.113.100 there", sourceIp: null }), null);
  assert.equal(findIoc(iocs, { message: "lookup evil.example now", sourceIp: null })?.kind, "domain");
  assert.equal(findIoc(iocs, { message: "notevil.example", sourceIp: null }), null);
  assert.equal(findIoc(iocs, { message: `hash ${"a".repeat(64)}`, sourceIp: null })?.kind, "hash");
  assert.equal(findIoc(iocs, { message: "rule 1 fired", sourceIp: null }), null);
  const expired = [{ kind: "ip", value: "198.51.100.10", expiresAt: "2000-01-01T00:00:00.000Z" }];
  assert.equal(findIoc(expired, { message: "", sourceIp: "198.51.100.10" }), null);
});

test("IOC values that are too vague are rejected", () => {
  assert.equal(validateIoc("ip", "127.0.0.1"), "Loopback is not an IOC");
  assert.equal(validateIoc("domain", "com"), "Enter a domain like evil.example");
  assert.equal(validateIoc("hash", "abcd"), "Hash must be 32 to 128 hex characters");
  assert.equal(validateIoc("other", "abc"), "Value must be at least 6 characters");
  assert.equal(validateIoc("ip", "203.0.113.10"), null);
});

test("inventory matching requires the product, not a shared token", () => {
  assert.equal(matchInventory("Google Chrome", "131.0.0", "Google", "Google Chrome", "Chrome bug")?.confidence, "high");
  assert.equal(matchInventory("nginx", "1.27.0", "F5", "nginx", "nginx")?.confidence, "high");
  assert.equal(matchInventory("Notes", "1.0", "Example", "Windows Server 2019", "Windows Server 2019"), null);
  assert.equal(matchInventory("Helper", "1.0", "Acme", "Helper Service", "Helper"), null);
  assert.equal(matchInventory("nginx", "1.27.0", "F5", "nginx", "nginx 2.1 overflow"), null);
});
