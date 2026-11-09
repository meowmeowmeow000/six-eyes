/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validateSixEyesProfile,
  processTcpSequenceDesync,
  evaluateMiddleboxEvasion,
} from './desyncEngine';

test('validateSixEyesProfile accepts valid profile parameters', () => {
  const result = validateSixEyesProfile({
    name: 'six-eyes-stealth',
    strategy: 'FAKE_RST',
    splitOffset: 2,
    fakeRstTtl: 3,
  });
  assert.equal(result.valid, true);
  assert.equal(result.errors.length, 0);
});

test('validateSixEyesProfile rejects invalid profile parameters', () => {
  const result = validateSixEyesProfile({
    name: '',
    strategy: 'INVALID_STRATEGY' as any,
    splitOffset: 5000,
    fakeRstTtl: 0,
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.length >= 3);
});

test('processTcpSequenceDesync generates correct packets for FAKE_RST strategy', () => {
  const initialSeq = 1000;
  const initialAck = 5000;
  const payload = 'GET /api/v1/user HTTP/1.1\r\nHost: example.com\r\n\r\n';

  const session = processTcpSequenceDesync(
    initialSeq,
    initialAck,
    'FAKE_RST',
    payload,
    2,
    3
  );

  assert.equal(session.strategy, 'FAKE_RST');
  assert.equal(session.isDesynchronized, true);
  assert.equal(session.packetsGenerated.length, 3);

  const fakeRst = session.packetsGenerated.find((p) => p.flags.rst);
  assert.ok(fakeRst, 'Fake RST packet must be injected');
  assert.equal(fakeRst.ttl, 3);
  assert.equal(fakeRst.isDesyncInjection, true);

  const realData = session.packetsGenerated.find((p) => p.payloadLength > 0);
  assert.ok(realData, 'Real payload packet must exist');
  assert.equal(realData.payloadLength, payload.length);
  assert.equal(realData.ttl, 64);
});

test('processTcpSequenceDesync correctly splits payload for HTTP_SPLIT strategy', () => {
  const initialSeq = 2000;
  const initialAck = 8000;
  const payload = 'POST /login HTTP/1.1\r\nHost: example.com';
  const splitOffset = 4;

  const session = processTcpSequenceDesync(
    initialSeq,
    initialAck,
    'HTTP_SPLIT',
    payload,
    splitOffset
  );

  assert.equal(session.strategy, 'HTTP_SPLIT');
  assert.equal(session.packetsGenerated.length, 3);

  const frag1 = session.packetsGenerated[1];
  const frag2 = session.packetsGenerated[2];

  assert.equal(frag1.payloadLength, splitOffset);
  assert.equal(frag2.payloadLength, payload.length - splitOffset);
  assert.equal(frag1.seqNum + frag1.payloadLength, frag2.seqNum);
});

test('evaluateMiddleboxEvasion reports high stealth score with desync active', () => {
  const withDesync = evaluateMiddleboxEvasion(true, 'FAKE_RST', 'blocked-site.org', 3);
  const withoutDesync = evaluateMiddleboxEvasion(false, 'FAKE_RST', 'blocked-site.org', 3);

  assert.ok(
    withDesync.stealthScore > withoutDesync.stealthScore,
    'TCP desync must increase stealthScore'
  );
  assert.ok(
    withDesync.evasionSuccessRate > withoutDesync.evasionSuccessRate,
    'TCP desync must increase evasionSuccessRate'
  );
  assert.equal(withDesync.fakeRstPoisoned, true);
});
