import test from "node:test"; import assert from "node:assert/strict";
import { checkRecipient, isLookalike, checksumOk } from "../src/index.js";
const REAL = "0xd9A1b0B1e1aE382DbDc898Ea68012FfcB2853a91", FAKE = "0xd9A1C3788D81257612E2581A6ea0aDa244853a91";
test("flags the 2024 WBTC poisoning lookalike", () => { const r = checkRecipient(FAKE, [REAL]); assert.equal(r.verdict, "danger"); assert.equal(r.lookalikes[0].shared_prefix, 4); assert.equal(r.lookalikes[0].shared_suffix, 6); });
test("exact match", () => { assert.equal(checkRecipient(REAL, [REAL.toLowerCase()]).verdict, "match"); });
test("unrelated is not lookalike", () => { assert.equal(isLookalike(REAL, "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"), false); });
test("checksum", () => { assert.equal(checksumOk("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"), true); assert.equal(checksumOk("0x833589FCD6eDb6E08f4c7C32D4f71b54bdA02913"), false); assert.equal(checksumOk(REAL.toLowerCase()), null); });
test("bad checksum is danger", () => { assert.equal(checkRecipient("0x833589FCD6eDb6E08f4c7C32D4f71b54bdA02913").verdict, "danger"); });
