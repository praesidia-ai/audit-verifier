/**
 * Minimal PKZIP reader and writer.
 *
 * Matches the STORED-method (method 0) entries produced by be-core's
 * `ZipStreamWriter` (AGV-035). No compression at the zip layer, no
 * encryption, no ZIP64, UTF-8 filenames, CRC-32 mandatory.
 *
 * We deliberately avoid third-party libs (yauzl / jszip / adm-zip) so
 * the verifier keeps a zero-dependency footprint.
 */

import * as zlib from 'node:zlib';

// ── ZIP local file header signature       'PK\x03\x04'  (little-endian) ─
const LFH_SIG = 0x04034b50;
// ── ZIP central directory header signature 'PK\x01\x02'                  ─
const CDH_SIG = 0x02014b50;
// ── ZIP end-of-central-directory record    'PK\x05\x06'                  ─
const EOCD_SIG = 0x06054b50;

export interface ZipEntry {
  name: string;
  /** STORED-method raw bytes (no compression at the zip layer). */
  data: Buffer;
}

export class ZipReadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ZipReadError';
  }
}

/**
 * Parse a PKZIP archive in-memory. Supports only the subset produced by
 * `ZipStreamWriter`: STORED method, no encryption, no ZIP64. Anything
 * else throws {@link ZipReadError}.
 *
 * @param buffer  The raw zip bytes.
 * @returns       Ordered list of entries as they appeared in the
 *                central directory.
 */
export function readZip(buffer: Buffer): ZipEntry[] {
  if (buffer.length < 22) {
    throw new ZipReadError('zip too small to contain an EOCD record');
  }
  const eocdOffset = findEocd(buffer);
  if (eocdOffset < 0) {
    throw new ZipReadError('end-of-central-directory record not found');
  }

  const totalEntries = buffer.readUInt16LE(eocdOffset + 10);
  const cdSize = buffer.readUInt32LE(eocdOffset + 12);
  const cdOffset = buffer.readUInt32LE(eocdOffset + 16);

  if (cdOffset + cdSize > buffer.length) {
    throw new ZipReadError('central directory extends past file end');
  }

  const entries: ZipEntry[] = [];
  let p = cdOffset;
  for (let i = 0; i < totalEntries; i++) {
    if (p + 46 > buffer.length) {
      throw new ZipReadError('truncated central directory entry');
    }
    if (buffer.readUInt32LE(p) !== CDH_SIG) {
      throw new ZipReadError('bad central directory signature');
    }
    const method = buffer.readUInt16LE(p + 10);
    if (method !== 0 && method !== 8) {
      // We accept STORED (the format ZipStreamWriter produces) and
      // also DEFLATE in case a future archiver re-compresses our
      // ndjson.gz entries at the zip layer. Anything else is a hard
      // error so we don't silently mis-read encrypted or otherwise
      // exotic content.
      throw new ZipReadError(
        `unsupported zip compression method ${method} (expected STORED or DEFLATE)`,
      );
    }
    const compressedSize = buffer.readUInt32LE(p + 20);
    const uncompressedSize = buffer.readUInt32LE(p + 24);
    const nameLen = buffer.readUInt16LE(p + 28);
    const extraLen = buffer.readUInt16LE(p + 30);
    const commentLen = buffer.readUInt16LE(p + 32);
    const localHeaderOffset = buffer.readUInt32LE(p + 42);
    const name = buffer.toString('utf8', p + 46, p + 46 + nameLen);
    p += 46 + nameLen + extraLen + commentLen;

    // Walk into the local file header to find the data offset.
    if (localHeaderOffset + 30 > buffer.length) {
      throw new ZipReadError(`local header for ${name} past file end`);
    }
    if (buffer.readUInt32LE(localHeaderOffset) !== LFH_SIG) {
      throw new ZipReadError(`bad local file header signature for ${name}`);
    }
    const lfhNameLen = buffer.readUInt16LE(localHeaderOffset + 26);
    const lfhExtraLen = buffer.readUInt16LE(localHeaderOffset + 28);
    const dataStart = localHeaderOffset + 30 + lfhNameLen + lfhExtraLen;
    if (dataStart + compressedSize > buffer.length) {
      throw new ZipReadError(`data for ${name} past file end`);
    }
    const rawData = buffer.subarray(dataStart, dataStart + compressedSize);
    let data: Buffer;
    if (method === 0) {
      data = Buffer.from(rawData);
      if (data.length !== uncompressedSize) {
        throw new ZipReadError(
          `STORED entry ${name} size mismatch: ${data.length} vs ${uncompressedSize}`,
        );
      }
    } else {
      // method 8 — DEFLATE
      data = zlib.inflateRawSync(rawData);
      if (data.length !== uncompressedSize) {
        throw new ZipReadError(
          `DEFLATE entry ${name} size mismatch: ${data.length} vs ${uncompressedSize}`,
        );
      }
    }
    entries.push({ name, data });
  }
  return entries;
}

/**
 * Find the EOCD record by scanning backward from end-of-file. The EOCD
 * signature can be at most `0xFFFF + 22` bytes from EOF (zip file
 * comment is bounded to 16 bits). We scan a generous window.
 */
function findEocd(buffer: Buffer): number {
  const minStart = Math.max(0, buffer.length - 0xffff - 22);
  for (let i = buffer.length - 22; i >= minStart; i--) {
    if (buffer.readUInt32LE(i) === EOCD_SIG) {
      return i;
    }
  }
  return -1;
}

// ════════════════════════════════════════════════════════════════════════
// Test-only ZIP writer — same wire format as be-core's ZipStreamWriter,
// flattened into a single in-memory Buffer (no streaming concerns since
// it's only used by the test fixture builder).
// ════════════════════════════════════════════════════════════════════════

/** CRC-32 table (IEEE 802.3 polynomial). */
const CRC32_TABLE: number[] = (() => {
  const tbl = new Array<number>(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    tbl[n] = c >>> 0;
  }
  return tbl;
})();

function computeCrc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = CRC32_TABLE[(c ^ buf[i]!) & 0xff]! ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

/**
 * Serialize a set of named buffers as a PKZIP archive (STORED method).
 * Reproducible: timestamps are pinned to `1980-01-01 00:00:00`, matching
 * `ZipStreamWriter`. Same input → byte-identical output.
 *
 * NOT exported from `index.ts` — fixture-builder helper only.
 */
export function writeZip(entries: ZipEntry[]): Buffer {
  const chunks: Buffer[] = [];
  let offset = 0;
  const central: Array<{
    name: string;
    crc32: number;
    size: number;
    localHeaderOffset: number;
  }> = [];

  for (const entry of entries) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const crc32 = computeCrc32(entry.data);
    const localHeaderOffset = offset;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(LFH_SIG, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // UTF-8 filename
    local.writeUInt16LE(0, 8); // STORED
    local.writeUInt16LE(0, 10); // mod time
    local.writeUInt16LE(0x21, 12); // mod date (Jan 1, 1980)
    local.writeUInt32LE(crc32, 14);
    local.writeUInt32LE(entry.data.length, 18);
    local.writeUInt32LE(entry.data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(0, 28);

    chunks.push(local, nameBuf, entry.data);
    offset += local.length + nameBuf.length + entry.data.length;

    central.push({
      name: entry.name,
      crc32,
      size: entry.data.length,
      localHeaderOffset,
    });
  }

  const centralStart = offset;
  for (const entry of central) {
    const nameBuf = Buffer.from(entry.name, 'utf8');
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(CDH_SIG, 0);
    cd.writeUInt16LE(20, 4);
    cd.writeUInt16LE(20, 6);
    cd.writeUInt16LE(0x0800, 8);
    cd.writeUInt16LE(0, 10);
    cd.writeUInt16LE(0, 12);
    cd.writeUInt16LE(0x21, 14);
    cd.writeUInt32LE(entry.crc32, 16);
    cd.writeUInt32LE(entry.size, 20);
    cd.writeUInt32LE(entry.size, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt16LE(0, 30);
    cd.writeUInt16LE(0, 32);
    cd.writeUInt16LE(0, 34);
    cd.writeUInt16LE(0, 36);
    cd.writeUInt32LE(0, 38);
    cd.writeUInt32LE(entry.localHeaderOffset, 42);
    chunks.push(cd, nameBuf);
    offset += cd.length + nameBuf.length;
  }
  const centralSize = offset - centralStart;

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(EOCD_SIG, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(central.length, 8);
  eocd.writeUInt16LE(central.length, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(centralStart, 16);
  eocd.writeUInt16LE(0, 20);
  chunks.push(eocd);

  return Buffer.concat(chunks);
}

/** Gzip a buffer (test fixture helper). Deterministic — no extra fields. */
export function gzipDeterministic(data: Buffer): Buffer {
  // Use mtime=0 so the gzip header is reproducible.
  return zlib.gzipSync(data, { level: 9 });
}

/** Gunzip a buffer (verifier reads `*.gz` entries). */
export function gunzip(data: Buffer): Buffer {
  return zlib.gunzipSync(data);
}
