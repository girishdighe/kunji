import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CHARSETS, DEFAULT_LENGTH, MIN_LENGTH, MAX_LENGTH, DEFAULT_RULES, PROFILE,
  normaliseInput, requiredClasses, classChars,
} from '../src/derive.js';

test('profile id is v1', () => {
  assert.equal(PROFILE, 'v1');
});

test('charsets are the exact frozen strings', () => {
  assert.equal(
    CHARSETS.standard,
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*+-=?@_',
  );
  assert.equal(
    CHARSETS['letters-digits'],
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  );
  assert.equal(
    CHARSETS['max-symbols'],
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&*()-_=+[]{};:,.?@',
  );
});

test('charset lengths', () => {
  assert.equal(CHARSETS.standard.length, 74);
  assert.equal(CHARSETS['letters-digits'].length, 62);
  assert.equal(CHARSETS['max-symbols'].length, 84);
});

test('defaults', () => {
  assert.equal(DEFAULT_LENGTH, 20);
  assert.equal(MIN_LENGTH, 8);
  assert.equal(MAX_LENGTH, 64);
  assert.equal(DEFAULT_RULES, 'standard');
});

test('normaliseInput: NFKC, trim, lowercase', () => {
  assert.equal(normaliseInput('  GitHub.com  '), 'github.com');
  assert.equal(normaliseInput('ﬁle'), 'file');        // fi ligature -> "fi"
  assert.equal(normaliseInput('ＦＵＬＬ'), 'full');           // full-width -> ascii
  assert.equal(normaliseInput('Ä'), 'ä');
});

test('requiredClasses', () => {
  assert.deepEqual(requiredClasses('standard'), ['lower', 'upper', 'digit', 'symbol']);
  assert.deepEqual(requiredClasses('max-symbols'), ['lower', 'upper', 'digit', 'symbol']);
  assert.deepEqual(requiredClasses('letters-digits'), ['lower', 'upper', 'digit']);
});

test('classChars: symbol pool is the non-alnum chars of the active charset', () => {
  assert.equal(classChars('lower', CHARSETS.standard), 'abcdefghijklmnopqrstuvwxyz');
  assert.equal(classChars('upper', CHARSETS.standard), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
  assert.equal(classChars('digit', CHARSETS.standard), '0123456789');
  assert.equal(classChars('symbol', CHARSETS.standard), '!#$%&*+-=?@_');
  assert.equal(classChars('symbol', CHARSETS['letters-digits']), '');
});
