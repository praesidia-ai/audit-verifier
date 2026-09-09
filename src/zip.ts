/**
 * Minimal PKZIP reader and writer.
 *
 * Matches the STORED-method (method 0) entries produced by be-core's
 * `ZipStreamWriter` (AGV-035). No compression at the zip layer, no
 * encryption, UTF-8 filenames, CRC-32 mandatory.
 *
 * AUDIT-2026-05-15 — adds ZIP64 (APPNOTE 4.5) framing support. Resource
 * ceilings still apply before entry data is exposed, so ZIP64 metadata is
 * accepted without allowing multi-gigabyte allocations. The writer in
 * `bundle-exporter.service.ts` only emits ZIP64 records when needed, so
 * small bundles remain byte-identical to the pre-AUDIT-15 layout.
 *
 * We deliberately avoid third-party libs (yauzl / jszip / adm-zip) so
 * the verifier keeps a zero-dependency footprint.
 */

import * as zlib from 'node:zlib';
import { Readable } from 'node:stream';
import { TextDecoder } from 'node:util';

// ── ZIP local file header signature       'PK\x03\x04'  (little-endian) ─
const LFH_SIG = 0x04034b50;
// ── ZIP central directory header signature 'PK\x01\x02'                  ─
const CDH_SIG = 0x02014b50;
// ── ZIP end-of-central-directory record    'PK\x05\x06'                  ─
const EOCD_SIG = 0x06054b50;
// ── ZIP64 EOCD locator                     'PK\x06\x07'                  ─
const ZIP64_LOCATOR_SIG = 0x07064b50;
// ── ZIP64 EOCD record                      'PK\x06\x06'                  ─
const ZIP64_EOCD_SIG = 0x06064b50;

// Sentinels used in classic headers to signal that the real value is
// carried in the ZIP64 extra field / ZIP64 EOCD record.
const ZIP64_U32_LIMIT = 0xffffffff;
const ZIP64_U16_LIMIT = 0xffff;

// ZIP64 extra field header ID (APPNOTE 4.5.3).
const ZIP64_EXTRA_ID = 0x0001;

export interface ZipEntry {
  name: string;
  /** Uncompressed entry bytes; STORED entries are zero-copy archive views. */
  data: Buffer;
}

export class ZipReadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ZipReadError';
  }
}

export interface ZipReadLimits {
  maxArchiveBytes?: number;
  maxEntries?: number;
  maxEntryNameBytes?: number;
  maxEntryUncompressedBytes?: number;
  maxTotalUncompressedBytes?: number;
  /** Optional exact-name allow-list, enforced before any entry payload is copied/inflated. */
  allowedEntryNames?: ReadonlySet<string>;
  /** Optional tighter per-entry caps, enforced before any entry payload is copied/inflated. */
  maxEntryUncompressedBytesByName?: ReadonlyMap<string, number>;
}

// The library API receives a Buffer and the CLI snapshots the file into one,
// so the raw archive itself must be small enough to coexist with parsed JSON
// on an ordinary Node heap. Current producers cap gzip artifacts at 64 MiB
// aggregate and metadata at 2 MiB; 72 MiB leaves deterministic framing room
// without restoring the former multi-gigabyte allocation surface.
export const MAX_ZIP_ARCHIVE_BYTES = 72 * 1024 * 1024;
export const MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES = 32 * 1024 * 1024;
export const MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES = 68 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES = 64;
const DEFAULT_MAX_ENTRY_NAME_BYTES = 4096;
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true });

export interface GzipOutputBudget {
  /** Remaining decoded bytes shared by every nested gzip member. */
  remainingBytes: number;
}

export interface GzipReadLimits {
  entryName: string;
  maxCompressedBytes: number;
  maxOutputBytes: number;
  outputBudget: GzipOutputBudget;
}

/**
 * Parse a PKZIP archive in-memory. Supports the subset produced by
 * `ZipStreamWriter`: STORED method, no encryption, UTF-8 filenames, with
 * optional ZIP64 extensions. ZIP-layer compression is rejected: evidence
 * members already use gzip and are expanded by the bounded streaming path.
 * Anything else throws {@link ZipReadError}.
 *
 * @param buffer  The raw zip bytes.
 * @returns       Ordered list of entries as they appeared in the
 *                central directory.
 */
export function readZip(
  buffer: Buffer,
  limits: ZipReadLimits = {},
): ZipEntry[] {
  const maxArchiveBytes = limits.maxArchiveBytes ?? MAX_ZIP_ARCHIVE_BYTES;
  const maxEntries = limits.maxEntries ?? DEFAULT_MAX_ENTRIES;
  const maxEntryNameBytes =
    limits.maxEntryNameBytes ?? DEFAULT_MAX_ENTRY_NAME_BYTES;
  const maxEntryBytes =
    limits.maxEntryUncompressedBytes ?? MAX_ZIP_ENTRY_UNCOMPRESSED_BYTES;
  const maxTotalBytes =
    limits.maxTotalUncompressedBytes ?? MAX_ZIP_TOTAL_UNCOMPRESSED_BYTES;
  if (
    !Number.isSafeInteger(maxArchiveBytes) ||
    maxArchiveBytes <= 0 ||
    !Number.isSafeInteger(maxEntries) ||
    maxEntries <= 0 ||
    !Number.isSafeInteger(maxEntryNameBytes) ||
    maxEntryNameBytes <= 0 ||
    !Number.isSafeInteger(maxEntryBytes) ||
    maxEntryBytes <= 0 ||
    !Number.isSafeInteger(maxTotalBytes) ||
    maxTotalBytes <= 0
  ) {
    throw new ZipReadError('invalid zip resource limits');
  }
  if (limits.maxEntryUncompressedBytesByName) {
    for (const [name, limit] of limits.maxEntryUncompressedBytesByName) {
      if (
        typeof name !== 'string' ||
        name.length === 0 ||
        !Number.isSafeInteger(limit) ||
        limit <= 0
      ) {
        throw new ZipReadError('invalid per-entry zip resource limit');
      }
    }
  }
  if (buffer.length > maxArchiveBytes) {
    throw new ZipReadError(
      `zip archive size ${buffer.length} exceeds limit ${maxArchiveBytes}`,
    );
  }
  if (buffer.length < 22) {
    throw new ZipReadError('zip too small to contain an EOCD record');
  }
  const eocdOffset = findEocd(buffer);
  if (eocdOffset < 0) {
    throw new ZipReadError('end-of-central-directory record not found');
  }

  let totalEntries = buffer.readUInt16LE(eocdOffset + 10);
  let cdSize = buffer.readUInt32LE(eocdOffset + 12);
  let cdOffset = buffer.readUInt32LE(eocdOffset + 16);
  let centralDirectoryEndLimit = eocdOffset;
  if (
    buffer.readUInt16LE(eocdOffset + 4) !== 0 ||
    buffer.readUInt16LE(eocdOffset + 6) !== 0 ||
    buffer.readUInt16LE(eocdOffset + 8) !== totalEntries
  ) {
    throw new ZipReadError('multi-disk zip archives are not supported');
  }

  // AUDIT-2026-05-15: if ANY classic EOCD field is a sentinel, look
  // for a ZIP64 EOCD locator immediately before the classic EOCD.
  // APPNOTE 4.3.16 — the locator is 20 bytes and sits at
  // (eocdOffset - 20). Its presence is authoritative: even if only
  // one field overflowed in the classic record, the locator promotes
  // every count/size/offset to the ZIP64 values.
  const classicHasSentinel =
    totalEntries === ZIP64_U16_LIMIT ||
    cdSize === ZIP64_U32_LIMIT ||
    cdOffset === ZIP64_U32_LIMIT;
  if (classicHasSentinel) {
    const locatorOffset = eocdOffset - 20;
    if (
      locatorOffset < 0 ||
      buffer.readUInt32LE(locatorOffset) !== ZIP64_LOCATOR_SIG
    ) {
      throw new ZipReadError(
        'classic EOCD has ZIP64 sentinel(s) but ZIP64 EOCD locator not found',
      );
    }
    const zip64EocdOffset = safeZip64Number(
      buffer.readBigUInt64LE(locatorOffset + 8),
      'EOCD offset',
    );
    if (
      zip64EocdOffset < 0 ||
      zip64EocdOffset + 56 > buffer.length ||
      buffer.readUInt32LE(zip64EocdOffset) !== ZIP64_EOCD_SIG
    ) {
      throw new ZipReadError(
        'ZIP64 EOCD locator points to invalid ZIP64 EOCD record',
      );
    }
    const zip64RecordSize = safeZip64Number(
      buffer.readBigUInt64LE(zip64EocdOffset + 4),
      'EOCD record size',
    );
    if (
      zip64RecordSize < 44 ||
      zip64EocdOffset + 12 + zip64RecordSize !== locatorOffset
    ) {
      throw new ZipReadError(
        'ZIP64 EOCD record size is invalid or does not end at its locator',
      );
    }
    if (
      buffer.readUInt32LE(zip64EocdOffset + 16) !== 0 ||
      buffer.readUInt32LE(zip64EocdOffset + 20) !== 0 ||
      buffer.readBigUInt64LE(zip64EocdOffset + 24) !==
        buffer.readBigUInt64LE(zip64EocdOffset + 32) ||
      buffer.readUInt32LE(locatorOffset + 4) !== 0 ||
      buffer.readUInt32LE(locatorOffset + 16) !== 1
    ) {
      throw new ZipReadError('multi-disk ZIP64 archives are not supported');
    }
    centralDirectoryEndLimit = zip64EocdOffset;
    // We accept ANY zip64 EOCD record size >= 44 bytes (the minimum
    // record body) — readers MUST tolerate extensible-data appended
    // after the documented fields (APPNOTE 4.3.14.3).
    totalEntries = safeZip64Number(
      buffer.readBigUInt64LE(zip64EocdOffset + 32),
      'entry count',
    );
    cdSize = safeZip64Number(
      buffer.readBigUInt64LE(zip64EocdOffset + 40),
      'central-directory size',
    );
    cdOffset = safeZip64Number(
      buffer.readBigUInt64LE(zip64EocdOffset + 48),
      'central-directory offset',
    );
  }

  if (totalEntries > maxEntries) {
    throw new ZipReadError(
      `zip entry count ${totalEntries} exceeds limit ${maxEntries}`,
    );
  }

  if (
    cdOffset > centralDirectoryEndLimit ||
    cdSize > centralDirectoryEndLimit - cdOffset
  ) {
    throw new ZipReadError('central directory extends past file end');
  }

  const entries: ZipEntry[] = [];
  const names = new Set<string>();
  let totalUncompressed = 0;
  let p = cdOffset;
  for (let i = 0; i < totalEntries; i++) {
    if (p + 46 > buffer.length) {
      throw new ZipReadError('truncated central directory entry');
    }
    if (buffer.readUInt32LE(p) !== CDH_SIG) {
      throw new ZipReadError('bad central directory signature');
    }
    const flags = buffer.readUInt16LE(p + 8);
    if ((flags & 0x0001) !== 0) {
      throw new ZipReadError('encrypted zip entries are not supported');
    }
    const method = buffer.readUInt16LE(p + 10);
    const expectedCrc = buffer.readUInt32LE(p + 16);
    if (method !== 0) {
      // Evidence streams are already gzip members. Accepting another archive
      // compression layer would require materializing an intermediate entry
      // before its nested budget can run, so fail closed on every non-STORED
      // method.
      throw new ZipReadError(
        `unsupported zip compression method ${method} (expected STORED)`,
      );
    }
    let compressedSize = buffer.readUInt32LE(p + 20);
    let uncompressedSize = buffer.readUInt32LE(p + 24);
    const nameLen = buffer.readUInt16LE(p + 28);
    const extraLen = buffer.readUInt16LE(p + 30);
    const commentLen = buffer.readUInt16LE(p + 32);
    let localHeaderOffset = buffer.readUInt32LE(p + 42);
    const cdhEnd = p + 46 + nameLen + extraLen + commentLen;
    if (cdhEnd > cdOffset + cdSize || cdhEnd > buffer.length) {
      throw new ZipReadError('central directory entry extends past its bounds');
    }
    let name: string;
    if (nameLen > maxEntryNameBytes) {
      throw new ZipReadError(
        `zip entry name length ${nameLen} exceeds limit ${maxEntryNameBytes}`,
      );
    }
    try {
      name = UTF8_DECODER.decode(buffer.subarray(p + 46, p + 46 + nameLen));
    } catch {
      throw new ZipReadError('zip entry name is not valid UTF-8');
    }
    if (name.length === 0 || name.includes('\0')) {
      throw new ZipReadError('zip entry has an invalid empty/NUL name');
    }
    if (limits.allowedEntryNames && !limits.allowedEntryNames.has(name)) {
      throw new ZipReadError(`unexpected zip entry name: ${name}`);
    }
    if (names.has(name)) {
      throw new ZipReadError(`duplicate zip entry name: ${name}`);
    }
    names.add(name);

    // AUDIT-2026-05-15: walk the central-dir extra-fields region for
    // a ZIP64 extra (header ID 0x0001) — promote each 32-bit sentinel
    // to its 64-bit value in the documented order (uncompressed,
    // compressed, local-header offset, disk-start). The order is
    // FIXED by APPNOTE 4.5.3 and only present-values are encoded, so
    // we MUST consume them in the same order in which the classic
    // header had sentinels.
    const cdhExtraStart = p + 46 + nameLen;
    const zip64 = findZip64Extra(buffer, cdhExtraStart, extraLen);
    if (zip64) {
      let zp = zip64.dataStart;
      const zEnd = zip64.dataStart + zip64.dataSize;
      if (uncompressedSize === ZIP64_U32_LIMIT) {
        if (zp + 8 > zEnd) {
          throw new ZipReadError(
            `ZIP64 extra for ${name} truncated reading uncompressedSize`,
          );
        }
        uncompressedSize = safeZip64Number(
          buffer.readBigUInt64LE(zp),
          `uncompressed size for ${name}`,
        );
        zp += 8;
      }
      if (compressedSize === ZIP64_U32_LIMIT) {
        if (zp + 8 > zEnd) {
          throw new ZipReadError(
            `ZIP64 extra for ${name} truncated reading compressedSize`,
          );
        }
        compressedSize = safeZip64Number(
          buffer.readBigUInt64LE(zp),
          `compressed size for ${name}`,
        );
        zp += 8;
      }
      if (localHeaderOffset === ZIP64_U32_LIMIT) {
        if (zp + 8 > zEnd) {
          throw new ZipReadError(
            `ZIP64 extra for ${name} truncated reading localHeaderOffset`,
          );
        }
        localHeaderOffset = safeZip64Number(
          buffer.readBigUInt64LE(zp),
          `local-header offset for ${name}`,
        );
        zp += 8;
      }
    }

    p = cdhEnd;

    const namedMaxEntryBytes =
      limits.maxEntryUncompressedBytesByName?.get(name) ?? maxEntryBytes;
    const effectiveMaxEntryBytes = Math.min(maxEntryBytes, namedMaxEntryBytes);
    if (uncompressedSize > effectiveMaxEntryBytes) {
      throw new ZipReadError(
        `entry ${name} uncompressed size ${uncompressedSize} exceeds limit ${effectiveMaxEntryBytes}`,
      );
    }
    if (totalUncompressed > maxTotalBytes - uncompressedSize) {
      throw new ZipReadError('zip total uncompressed size exceeds limit');
    }
    totalUncompressed += uncompressedSize;

    // Walk into the local file header to find the data offset.
    if (localHeaderOffset >= cdOffset || localHeaderOffset + 30 > cdOffset) {
      throw new ZipReadError(`local header for ${name} past file end`);
    }
    if (buffer.readUInt32LE(localHeaderOffset) !== LFH_SIG) {
      throw new ZipReadError(`bad local file header signature for ${name}`);
    }
    const localFlags = buffer.readUInt16LE(localHeaderOffset + 6);
    const localMethod = buffer.readUInt16LE(localHeaderOffset + 8);
    if (localFlags !== flags || localMethod !== method) {
      throw new ZipReadError(`local/central header mismatch for ${name}`);
    }
    const lfhNameLen = buffer.readUInt16LE(localHeaderOffset + 26);
    const lfhExtraLen = buffer.readUInt16LE(localHeaderOffset + 28);
    if (lfhNameLen > maxEntryNameBytes) {
      throw new ZipReadError(
        `local zip entry name length ${lfhNameLen} exceeds limit ${maxEntryNameBytes}`,
      );
    }
    if (localHeaderOffset + 30 + lfhNameLen + lfhExtraLen > buffer.length) {
      throw new ZipReadError(`local header for ${name} is truncated`);
    }
    let localName: string;
    try {
      localName = UTF8_DECODER.decode(
        buffer.subarray(
          localHeaderOffset + 30,
          localHeaderOffset + 30 + lfhNameLen,
        ),
      );
    } catch {
      throw new ZipReadError(
        `local header name for ${name} is not valid UTF-8`,
      );
    }
    if (localName !== name) {
      throw new ZipReadError(`local/central filename mismatch for ${name}`);
    }
    // When bit 3 (data descriptor) is clear, APPNOTE requires the local
    // CRC/sizes to describe the same payload as the central directory.
    // Ignoring those fields admitted deliberately ambiguous archives that
    // different ZIP readers could interpret differently. ZIP64 sentinels are
    // resolved from the local extra field before comparison.
    if ((localFlags & 0x0008) === 0) {
      const localCrc = buffer.readUInt32LE(localHeaderOffset + 14);
      let localCompressedSize = buffer.readUInt32LE(localHeaderOffset + 18);
      let localUncompressedSize = buffer.readUInt32LE(localHeaderOffset + 22);
      if (
        localCompressedSize === ZIP64_U32_LIMIT ||
        localUncompressedSize === ZIP64_U32_LIMIT
      ) {
        const localExtraStart = localHeaderOffset + 30 + lfhNameLen;
        const localZip64 = findZip64Extra(buffer, localExtraStart, lfhExtraLen);
        if (!localZip64) {
          throw new ZipReadError(
            `local header for ${name} uses ZIP64 sentinel(s) without a ZIP64 extra field`,
          );
        }
        let lp = localZip64.dataStart;
        const localZip64End = lp + localZip64.dataSize;
        if (localUncompressedSize === ZIP64_U32_LIMIT) {
          if (lp + 8 > localZip64End) {
            throw new ZipReadError(
              `local ZIP64 extra for ${name} is truncated reading uncompressedSize`,
            );
          }
          localUncompressedSize = safeZip64Number(
            buffer.readBigUInt64LE(lp),
            `local uncompressed size for ${name}`,
          );
          lp += 8;
        }
        if (localCompressedSize === ZIP64_U32_LIMIT) {
          if (lp + 8 > localZip64End) {
            throw new ZipReadError(
              `local ZIP64 extra for ${name} is truncated reading compressedSize`,
            );
          }
          localCompressedSize = safeZip64Number(
            buffer.readBigUInt64LE(lp),
            `local compressed size for ${name}`,
          );
        }
      }
      if (
        localCrc !== expectedCrc ||
        localCompressedSize !== compressedSize ||
        localUncompressedSize !== uncompressedSize
      ) {
        throw new ZipReadError(
          `local/central CRC or size mismatch for ${name}`,
        );
      }
    }
    const dataStart = localHeaderOffset + 30 + lfhNameLen + lfhExtraLen;
    if (dataStart > cdOffset || compressedSize > cdOffset - dataStart) {
      throw new ZipReadError(`data for ${name} past file end`);
    }
    const rawData = buffer.subarray(dataStart, dataStart + compressedSize);
    // `buffer` already owns these immutable archive bytes. Returning a view
    // avoids retaining a second complete copy of every gzip member.
    const data = rawData;
    if (data.length !== uncompressedSize) {
      throw new ZipReadError(
        `STORED entry ${name} size mismatch: ${data.length} vs ${uncompressedSize}`,
      );
    }
    if (computeCrc32(data) !== expectedCrc) {
      throw new ZipReadError(`CRC-32 mismatch for ${name}`);
    }
    entries.push({ name, data });
  }
  if (p !== cdOffset + cdSize) {
    throw new ZipReadError('central directory size/count mismatch');
  }
  return entries;
}

function safeZip64Number(value: bigint, field: string): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new ZipReadError(`ZIP64 ${field} exceeds safe integer range`);
  }
  return Number(value);
}

/**
 * Find the EOCD record by scanning backward from end-of-file. The EOCD
 * signature can be at most `0xFFFF + 22` bytes from EOF (zip file
 * comment is bounded to 16 bits). We scan a generous window.
 */
function findEocd(buffer: Buffer): number {
  const minStart = Math.max(0, buffer.length - 0xffff - 22);
  for (let i = buffer.length - 22; i >= minStart; i--) {
    if (
      buffer.readUInt32LE(i) === EOCD_SIG &&
      i + 22 + buffer.readUInt16LE(i + 20) === buffer.length
    ) {
      return i;
    }
  }
  return -1;
}

/**
 * Walk an extra-fields region looking for the ZIP64 extra (header ID
 * 0x0001). Returns the position + length of the data payload, or null
 * when absent. Extra fields are a sequence of `{u16 id, u16 size,
 * size bytes payload}` records; unknown IDs MUST be skipped (APPNOTE
 * 4.5.1) so this loop is tolerant of producers that interleave their
 * own tags (e.g. Unix permissions).
 */
function findZip64Extra(
  buffer: Buffer,
  start: number,
  totalLen: number,
): { dataStart: number; dataSize: number } | null {
  let p = start;
  const end = start + totalLen;
  while (p + 4 <= end) {
    const id = buffer.readUInt16LE(p);
    const size = buffer.readUInt16LE(p + 2);
    if (p + 4 + size > end) {
      throw new ZipReadError('truncated zip extra field');
    }
    if (id === ZIP64_EXTRA_ID) {
      return { dataStart: p + 4, dataSize: size };
    }
    p += 4 + size;
  }
  if (p !== end) {
    throw new ZipReadError('truncated zip extra field header');
  }
  return null;
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
 * AUDIT-2026-05-15: when `forceZip64` is set, the produced archive
 * carries ZIP64 records on every entry plus a ZIP64 EOCD record +
 * locator before the classic EOCD. Used by tests to exercise the
 * verifier's ZIP64 read path without materialising a 4 GiB fixture.
 * The default (false) keeps the byte layout identical to pre-AUDIT-15
 * for fixtures that pinned bytes.
 *
 * NOT exported from `index.ts` — fixture-builder helper only.
 */
export function writeZip(
  entries: ZipEntry[],
  opts: { forceZip64?: boolean } = {},
): Buffer {
  const forceZip64 = opts.forceZip64 === true;
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
    const useZip64 = forceZip64 || entry.data.length >= ZIP64_U32_LIMIT;
    const extra = useZip64
      ? buildZip64Extra({
          uncompressedSize: entry.data.length,
          compressedSize: entry.data.length,
        })
      : Buffer.alloc(0);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(LFH_SIG, 0);
    local.writeUInt16LE(useZip64 ? 45 : 20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // UTF-8 filename
    local.writeUInt16LE(0, 8); // STORED
    local.writeUInt16LE(0, 10); // mod time
    local.writeUInt16LE(0x21, 12); // mod date (Jan 1, 1980)
    local.writeUInt32LE(crc32, 14);
    local.writeUInt32LE(useZip64 ? ZIP64_U32_LIMIT : entry.data.length, 18);
    local.writeUInt32LE(useZip64 ? ZIP64_U32_LIMIT : entry.data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    local.writeUInt16LE(extra.length, 28);

    chunks.push(local, nameBuf);
    if (extra.length > 0) chunks.push(extra);
    chunks.push(entry.data);
    offset += local.length + nameBuf.length + extra.length + entry.data.length;

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
    const sizeOverflow = forceZip64 || entry.size >= ZIP64_U32_LIMIT;
    const offsetOverflow =
      forceZip64 || entry.localHeaderOffset >= ZIP64_U32_LIMIT;
    const useZip64 = sizeOverflow || offsetOverflow;
    const extra = useZip64
      ? buildZip64Extra({
          uncompressedSize: sizeOverflow ? entry.size : undefined,
          compressedSize: sizeOverflow ? entry.size : undefined,
          localHeaderOffset: offsetOverflow
            ? entry.localHeaderOffset
            : undefined,
        })
      : Buffer.alloc(0);

    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(CDH_SIG, 0);
    cd.writeUInt16LE(useZip64 ? 45 : 20, 4);
    cd.writeUInt16LE(useZip64 ? 45 : 20, 6);
    cd.writeUInt16LE(0x0800, 8);
    cd.writeUInt16LE(0, 10);
    cd.writeUInt16LE(0, 12);
    cd.writeUInt16LE(0x21, 14);
    cd.writeUInt32LE(entry.crc32, 16);
    cd.writeUInt32LE(sizeOverflow ? ZIP64_U32_LIMIT : entry.size, 20);
    cd.writeUInt32LE(sizeOverflow ? ZIP64_U32_LIMIT : entry.size, 24);
    cd.writeUInt16LE(nameBuf.length, 28);
    cd.writeUInt16LE(extra.length, 30);
    cd.writeUInt16LE(0, 32);
    cd.writeUInt16LE(0, 34);
    cd.writeUInt16LE(0, 36);
    cd.writeUInt32LE(0, 38);
    cd.writeUInt32LE(
      offsetOverflow ? ZIP64_U32_LIMIT : entry.localHeaderOffset,
      42,
    );
    chunks.push(cd, nameBuf);
    if (extra.length > 0) chunks.push(extra);
    offset += cd.length + nameBuf.length + extra.length;
  }
  const centralSize = offset - centralStart;

  const archiveNeedsZip64 =
    forceZip64 ||
    centralStart >= ZIP64_U32_LIMIT ||
    centralSize >= ZIP64_U32_LIMIT ||
    central.length >= ZIP64_U16_LIMIT;

  if (archiveNeedsZip64) {
    const zip64Eocd = Buffer.alloc(56);
    zip64Eocd.writeUInt32LE(ZIP64_EOCD_SIG, 0);
    zip64Eocd.writeBigUInt64LE(BigInt(56 - 12), 4);
    zip64Eocd.writeUInt16LE(45, 12);
    zip64Eocd.writeUInt16LE(45, 14);
    zip64Eocd.writeUInt32LE(0, 16);
    zip64Eocd.writeUInt32LE(0, 20);
    zip64Eocd.writeBigUInt64LE(BigInt(central.length), 24);
    zip64Eocd.writeBigUInt64LE(BigInt(central.length), 32);
    zip64Eocd.writeBigUInt64LE(BigInt(centralSize), 40);
    zip64Eocd.writeBigUInt64LE(BigInt(centralStart), 48);
    const zip64EocdOffset = offset;
    chunks.push(zip64Eocd);
    offset += zip64Eocd.length;

    const locator = Buffer.alloc(20);
    locator.writeUInt32LE(ZIP64_LOCATOR_SIG, 0);
    locator.writeUInt32LE(0, 4);
    locator.writeBigUInt64LE(BigInt(zip64EocdOffset), 8);
    locator.writeUInt32LE(1, 16);
    chunks.push(locator);
    offset += locator.length;
  }

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(EOCD_SIG, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(
    central.length >= ZIP64_U16_LIMIT ? ZIP64_U16_LIMIT : central.length,
    8,
  );
  eocd.writeUInt16LE(
    central.length >= ZIP64_U16_LIMIT ? ZIP64_U16_LIMIT : central.length,
    10,
  );
  eocd.writeUInt32LE(
    centralSize >= ZIP64_U32_LIMIT || forceZip64
      ? ZIP64_U32_LIMIT
      : centralSize,
    12,
  );
  eocd.writeUInt32LE(
    centralStart >= ZIP64_U32_LIMIT || forceZip64
      ? ZIP64_U32_LIMIT
      : centralStart,
    16,
  );
  eocd.writeUInt16LE(0, 20);
  chunks.push(eocd);

  return Buffer.concat(chunks);
}

/**
 * Build a ZIP64 extra field (header ID 0x0001). Mirror of the writer
 * helper in `bundle-exporter.service.ts` — kept here so the verifier
 * package stays standalone (zero runtime deps + zero be-core imports).
 */
function buildZip64Extra(values: {
  uncompressedSize?: number;
  compressedSize?: number;
  localHeaderOffset?: number;
}): Buffer {
  const parts: number[] = [];
  if (values.uncompressedSize !== undefined)
    parts.push(values.uncompressedSize);
  if (values.compressedSize !== undefined) parts.push(values.compressedSize);
  if (values.localHeaderOffset !== undefined)
    parts.push(values.localHeaderOffset);
  const dataSize = parts.length * 8;
  const buf = Buffer.alloc(4 + dataSize);
  buf.writeUInt16LE(ZIP64_EXTRA_ID, 0);
  buf.writeUInt16LE(dataSize, 2);
  for (let i = 0; i < parts.length; i++) {
    buf.writeBigUInt64LE(BigInt(parts[i]!), 4 + i * 8);
  }
  return buf;
}

/** Gzip a buffer (test fixture helper). Deterministic — no extra fields. */
export function gzipDeterministic(data: Buffer): Buffer {
  // Use mtime=0 so the gzip header is reproducible.
  return zlib.gzipSync(data, { level: 9 });
}

/**
 * Incrementally expand one nested gzip member.
 *
 * The generator never materializes the decoded member. It emits at most one
 * zlib chunk at a time and debits both a per-entry ceiling and a caller-owned
 * aggregate budget before exposing each chunk. Throwing in the consumer (for
 * example on an oversized NDJSON record) destroys both streams immediately.
 */
export async function* gunzipChunks(
  data: Buffer,
  limits: GzipReadLimits,
): AsyncGenerator<Buffer, void, void> {
  if (
    typeof limits.entryName !== 'string' ||
    limits.entryName.length === 0 ||
    !Number.isSafeInteger(limits.maxCompressedBytes) ||
    limits.maxCompressedBytes <= 0 ||
    !Number.isSafeInteger(limits.maxOutputBytes) ||
    limits.maxOutputBytes <= 0 ||
    !Number.isSafeInteger(limits.outputBudget.remainingBytes) ||
    limits.outputBudget.remainingBytes < 0
  ) {
    throw new ZipReadError('invalid gzip resource limits');
  }
  if (data.length > limits.maxCompressedBytes) {
    throw new ZipReadError(
      `${limits.entryName} compressed size ${data.length} exceeds limit ${limits.maxCompressedBytes}`,
    );
  }

  // Feed compressed input in bounded views as well. A single 32 MiB write can
  // otherwise be retained/copied inside native zlib even though decoded
  // output is chunked correctly.
  const source = Readable.from(bufferViews(data, 64 * 1024));
  const inflater = zlib.createGunzip({ chunkSize: 64 * 1024 });
  const decoded = source.pipe(inflater);
  let entryOutputBytes = 0;
  try {
    for await (const value of decoded) {
      const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
      if (entryOutputBytes > limits.maxOutputBytes - chunk.length) {
        throw new ZipReadError(
          `${limits.entryName} expanded output exceeds per-entry limit ${limits.maxOutputBytes}`,
        );
      }
      if (limits.outputBudget.remainingBytes < chunk.length) {
        throw new ZipReadError(
          `bundle gzip output exceeds total resource limit while reading ${limits.entryName}`,
        );
      }
      entryOutputBytes += chunk.length;
      limits.outputBudget.remainingBytes -= chunk.length;
      yield chunk;
    }
  } catch (err) {
    if (err instanceof ZipReadError) throw err;
    throw new ZipReadError(
      `${limits.entryName} cannot be decompressed: ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  } finally {
    source.destroy();
    inflater.destroy();
  }
}

function* bufferViews(data: Buffer, chunkBytes: number): Generator<Buffer> {
  for (let offset = 0; offset < data.length; offset += chunkBytes) {
    yield data.subarray(offset, Math.min(offset + chunkBytes, data.length));
  }
}
