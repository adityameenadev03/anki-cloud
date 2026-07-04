// Copyright 2026 Archont Soft Daniel Klimuntowski
// Licensed under the Elastic License 2.0 — see LICENSE in the repository root.
import {eq} from "drizzle-orm";
import {OpenAPIHono, createRoute, z} from "@hono/zod-openapi";
import {db, userSyncConfig, userSyncState} from "@anki-cloud/db";
import {authWebMiddleware} from "@/middleware/auth";
import type {Env} from "@/types";

const CHARSET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const PASSWORD_LENGTH = 32;
const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;

const SyncPasswordSchema = z
    .string()
    .min(MIN_PASSWORD_LENGTH, `Password must be at least ${MIN_PASSWORD_LENGTH} characters`)
    .max(MAX_PASSWORD_LENGTH, `Password must be at most ${MAX_PASSWORD_LENGTH} characters`);

function generatePassword(): string {
    const bytes = crypto.getRandomValues(new Uint8Array(PASSWORD_LENGTH));
    return Array.from(bytes, (b) => CHARSET[b % CHARSET.length]).join("");
}

async function saveSyncPassword(userId: string, password: string): Promise<void> {
    const hash = await Bun.password.hash(password, {algorithm: "bcrypt", cost: 10});

    await db
        .insert(userSyncConfig)
        .values({userId, syncPasswordHash: hash})
        .onConflictDoUpdate({
            target: userSyncConfig.userId,
            set: {syncPasswordHash: hash},
        });

    // Invalidate any existing hkey so clients must re-authenticate.
    await db.update(userSyncState).set({syncKey: null}).where(eq(userSyncState.userId, userId));
}

const ErrorSchema = z.object({error: z.string(), code: z.string()});

const SyncCredentialsSchema = z.object({
    username: z.string().email().nullable(),
    password: z.string().nullable(),
    isSet: z.boolean(),
});

const SetSyncPasswordBodySchema = z.object({
    password: SyncPasswordSchema,
});

const ResetSyncPasswordBodySchema = z.object({
    password: SyncPasswordSchema.optional(),
});

const getSyncPasswordRoute = createRoute({
    method: "get",
    path: "/me/sync-password",
    middleware: [authWebMiddleware] as const,
    responses: {
        200: {
            content: {"application/json": {schema: SyncCredentialsSchema}},
            description: "Sync username and whether a password is configured. Password is never returned on GET.",
        },
        401: {
            content: {"application/json": {schema: ErrorSchema}},
            description: "Unauthenticated",
        },
    },
});

const setSyncPasswordRoute = createRoute({
    method: "post",
    path: "/me/sync-password",
    middleware: [authWebMiddleware] as const,
    request: {
        body: {
            content: {"application/json": {schema: SetSyncPasswordBodySchema}},
            required: true,
        },
    },
    responses: {
        200: {
            content: {"application/json": {schema: SyncCredentialsSchema}},
            description: "Sync password saved. Plaintext password echoed once in the response.",
        },
        401: {
            content: {"application/json": {schema: ErrorSchema}},
            description: "Unauthenticated",
        },
    },
});

const resetSyncPasswordRoute = createRoute({
    method: "post",
    path: "/me/sync-password/reset",
    middleware: [authWebMiddleware] as const,
    request: {
        body: {
            content: {"application/json": {schema: ResetSyncPasswordBodySchema}},
            required: true,
        },
    },
    responses: {
        200: {
            content: {"application/json": {schema: SyncCredentialsSchema}},
            description: "New sync credentials. Random password if body omitted; custom if password provided.",
        },
        401: {
            content: {"application/json": {schema: ErrorSchema}},
            description: "Unauthenticated",
        },
    },
});

export const syncCredentialsRouter = new OpenAPIHono<Env>();

syncCredentialsRouter.openapi(getSyncPasswordRoute, async (c) => {
    const {id, email} = c.get("user");

    const [config] = await db
        .select()
        .from(userSyncConfig)
        .where(eq(userSyncConfig.userId, id))
        .limit(1);

    const isSet = config?.syncPasswordHash !== null && config?.syncPasswordHash !== undefined;

    return c.json({username: email, password: null, isSet}, 200);
});

syncCredentialsRouter.openapi(setSyncPasswordRoute, async (c) => {
    const {id, email} = c.get("user");
    const {password} = c.req.valid("json");

    await saveSyncPassword(id, password);

    return c.json({username: email, password, isSet: true}, 200);
});

syncCredentialsRouter.openapi(resetSyncPasswordRoute, async (c) => {
    const {id, email} = c.get("user");
    const {password} = c.req.valid("json");
    const resolved = password ?? generatePassword();

    await saveSyncPassword(id, resolved);

    return c.json({username: email, password: resolved, isSet: true}, 200);
});