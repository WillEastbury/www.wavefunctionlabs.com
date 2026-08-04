import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

const conceptRoot = path.resolve('wwwroot', 'wavefunctionlabs.com', 'data', 'concepts');
const schemaPath = path.resolve('content', 'schema', 'concept-v2.schema.json');
const schema = JSON.parse(await readFile(schemaPath, 'utf8'));

function fail(file, location, message) {
  throw new Error(`${file}:${location || '/'}: ${message}`);
}

function resolveRef(ref) {
  if (!ref.startsWith('#/')) {
    throw new Error(`unsupported external schema reference: ${ref}`);
  }
  return ref.slice(2).split('/').reduce((value, segment) => value?.[segment], schema);
}

function matchesType(value, type) {
  if (type === 'null') return value === null;
  if (type === 'array') return Array.isArray(value);
  if (type === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value);
  if (type === 'integer') return Number.isInteger(value);
  return typeof value === type;
}

function validate(file, location, value, rule) {
  if (rule.$ref) {
    const resolved = resolveRef(rule.$ref);
    if (!resolved) fail(file, location, `unresolved schema reference ${rule.$ref}`);
    validate(file, location, value, resolved);
    return;
  }
  if ('const' in rule && value !== rule.const) {
    fail(file, location, `must equal ${JSON.stringify(rule.const)}`);
  }
  if (rule.enum && !rule.enum.includes(value)) {
    fail(file, location, `must be one of ${rule.enum.join(', ')}`);
  }
  if (rule.type) {
    const types = Array.isArray(rule.type) ? rule.type : [rule.type];
    if (!types.some(type => matchesType(value, type))) {
      fail(file, location, `must have type ${types.join(' or ')}`);
    }
  }

  if (typeof value === 'string') {
    if (rule.minLength && value.length < rule.minLength) {
      fail(file, location, `must contain at least ${rule.minLength} character(s)`);
    }
    if (rule.pattern && !(new RegExp(rule.pattern)).test(value)) {
      fail(file, location, `must match ${rule.pattern}`);
    }
    if (rule.format === 'date' && !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
      fail(file, location, 'must be an ISO date (YYYY-MM-DD)');
    }
  }

  if (Array.isArray(value) && rule.items) {
    value.forEach((item, index) => validate(file, `${location}/${index}`, item, rule.items));
  }

  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    for (const required of rule.required || []) {
      if (!(required in value)) fail(file, location, `missing required property ${required}`);
    }
    for (const [key, child] of Object.entries(value)) {
      const childRule = rule.properties?.[key];
      if (childRule) {
        validate(file, `${location}/${key}`, child, childRule);
      } else if (rule.additionalProperties && typeof rule.additionalProperties === 'object') {
        validate(file, `${location}/${key}`, child, rule.additionalProperties);
      } else if (rule.additionalProperties === false) {
        fail(file, location, `unexpected property ${key}`);
      }
    }
  }
}

const files = (await readdir(conceptRoot)).filter(file => file.endsWith('.json')).sort();
if (files.length === 0) {
  throw new Error(`no concept JSON files found in ${conceptRoot}`);
}

const seenIds = new Set();
const seenSlugs = new Set();
for (const file of files) {
  const raw = await readFile(path.join(conceptRoot, file), 'utf8');
  let concept;
  try {
    concept = JSON.parse(raw);
  } catch (error) {
    fail(file, '/', `invalid JSON: ${error.message}`);
  }
  validate(file, '', concept, schema);
  if (seenIds.has(concept.id)) fail(file, '/id', `duplicate id ${concept.id}`);
  if (seenSlugs.has(concept.slug)) fail(file, '/slug', `duplicate slug ${concept.slug}`);
  seenIds.add(concept.id);
  seenSlugs.add(concept.slug);
}

console.log(`Validated ${files.length} canonical concept object(s) against ${path.relative('.', schemaPath)}.`);
