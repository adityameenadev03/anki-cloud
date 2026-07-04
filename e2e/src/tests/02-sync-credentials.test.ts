// Copyright 2026 Archont Soft Daniel Klimuntowski
// Licensed under the Elastic License 2.0 — see LICENSE in the repository root.
/**
 * Tests for sync password set/generate/reset via REST API.
 * Users authenticate via Better Auth session (seeded directly into DB, skipping Google OAuth).
 */
import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { startStack, type TestStack } from "@/setup";
import { seedUser, createTestSession } from "@/helpers/auth";
import { makeApiClient } from "@/helpers/api";

describe("Sync credentials", () => {
  let stack: TestStack;
  let userId: string;
  let sessionToken: string;

  beforeAll(async () => {
    stack = await startStack();
    const user = await seedUser(stack.dbPath, { email: "sync-test@example.com" });
    userId = user.id;
    sessionToken = await createTestSession(stack.dbPath, userId);
  });

  afterAll(async () => {
    await stack.cleanup();
  });

  it("GET /v1/me/sync-password — returns username and isSet=false before password is set", async () => {
    const api = makeApiClient(`http://localhost:${stack.apiPort}`);
    const creds = await api.getSyncPassword(sessionToken);

    expect(creds.username).toBe("sync-test@example.com");
    expect(creds.password).toBeNull();
    expect(creds.isSet).toBe(false);
  });

  it("POST /v1/me/sync-password — set a custom password", async () => {
    const api = makeApiClient(`http://localhost:${stack.apiPort}`);
    const creds = await api.setSyncPassword(sessionToken, "my-secret-sync-pass");

    expect(creds.username).toBe("sync-test@example.com");
    expect(creds.password).toBe("my-secret-sync-pass");
    expect(creds.isSet).toBe(true);
  });

  it("GET /v1/me/sync-password — after set, returns isSet=true and null password", async () => {
    const api = makeApiClient(`http://localhost:${stack.apiPort}`);
    const creds = await api.getSyncPassword(sessionToken);

    expect(creds.username).toBe("sync-test@example.com");
    expect(creds.password).toBeNull();
    expect(creds.isSet).toBe(true);
  });

  it("POST /v1/me/sync-password/reset — returns new random plaintext password", async () => {
    const api = makeApiClient(`http://localhost:${stack.apiPort}`);
    const creds = await api.resetSyncPassword(sessionToken);

    expect(creds.username).toBe("sync-test@example.com");
    expect(typeof creds.password).toBe("string");
    expect((creds.password as string).length).toBe(32);
    expect(creds.isSet).toBe(true);
  });

  it("POST /v1/me/sync-password/reset — can set a custom password via reset body", async () => {
    const api = makeApiClient(`http://localhost:${stack.apiPort}`);
    const creds = await api.resetSyncPassword(sessionToken, "another-custom-pass");

    expect(creds.password).toBe("another-custom-pass");
    expect(creds.isSet).toBe(true);
  });

  it("Returns 401 without session cookie", async () => {
    const res = await fetch(
      `http://localhost:${stack.apiPort}/v1/me/sync-password`
    );
    expect(res.status).toBe(401);
  });
});