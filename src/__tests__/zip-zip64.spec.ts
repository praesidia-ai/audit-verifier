/**
 * AUDIT-2026-05-15 — ZIP64 read-path coverage.
 *
 * The bundle exporter (be-core's `ZipStreamWriter`) emits ZIP64 records
 * whenever an entry, the central directory, or the entry-count would
 * overflow the classic ZIP limits. The verifier's `readZip` MUST then:
 *
 *   1. Detect the ZIP64 EOCD locator at `eocdOffset - 20` when ANY
 *      classic EOCD field is a sentinel (count = 0xFFFF, size /
 *      offset = 0xFFFFFFFF).
 *   2. Follow it to the ZIP64 EOCD record and read the 64-bit count /
 *      size / offset of the central directory.
 *   3. For each central-dir entry, when ANY classic 32-bit
 *      size/offset field is the 0xFFFFFFFF sentinel, walk the ZIP64
 *      extra field (header ID 0x0001) and promote the value from its
 *      8-byte slot — in the documented order (uncompressed, compressed,
 *      local header offset).
 *
 * We exercise BOTH layers below:
 *   * `forceZip64` round-trips a tiny archive through the ZIP64 records
 *     without materialising 4 GiB of data.
 *   * Default-layout round-trips stay byte-identical (no ZIP64 overhead
 *     for small bundles).
 *   * A handcrafted >4 GiB sentinel-only header proves the reader
 *     refuses ZIP64-claimed archives that omit the locator.
 */

import { describe, expect, it } from 'vitest';
import { readZip, writeZip, ZipReadError } from '../zip.js';

describe('AUDIT-2026-05-15 ZIP64 read support', () => {
  it('default writeZip emits classic EOCD with no ZIP64 locator for small archives', () => {
    const zip = writeZip([
      { name: 'a.txt', data: Buffer.from('hello', 'utf8') },
      { name: 'b.txt', data: Buffer.from('world', 'utf8') },
    ]);
    // Last 22 bytes should be the classic EOCD with the real entry
    // count (2), not the 0xFFFF sentinel — proves we did NOT promote
    // to ZIP64 for a small archive (byte-stability preserved).
    const eocdOffset = zip.length - 22;
    expect(zip.readUInt32LE(eocdOffset)).toBe(0x06054b50);
    expect(zip.readUInt16LE(eocdOffset + 10)).toBe(2);

    const entries = readZip(zip);
    expect(entries.map((e) => e.name)).toEqual(['a.txt', 'b.txt']);
    expect(entries[0]!.data.toString('utf8')).toBe('hello');
    expect(entries[1]!.data.toString('utf8')).toBe('world');
  });

  it('forceZip64 round-trips through ZIP64 EOCD + locator', () => {
    const zip = writeZip(
      [
        { name: 'manifest.json', data: Buffer.from('{"v":1}', 'utf8') },
        { name: 'rows.ndjson', data: Buffer.from('row-1\nrow-2\n', 'utf8') },
      ],
      { forceZip64: true },
    );

    // Classic EOCD must carry the 0xFFFFFFFF sentinel for cdOffset
    // when forceZip64 is set, signalling the reader to consult the
    // ZIP64 locator immediately preceding it.
    const eocdOffset = zip.length - 22;
    expect(zip.readUInt32LE(eocdOffset)).toBe(0x06054b50);
    expect(zip.readUInt32LE(eocdOffset + 16)).toBe(0xffffffff);

    // 20 bytes before classic EOCD: ZIP64 EOCD locator signature.
    expect(zip.readUInt32LE(eocdOffset - 20)).toBe(0x07064b50);
    // The locator's 8-byte field at offset +8 points at the ZIP64
    // EOCD record, which must start with the 0x06064b50 signature.
    const zip64EocdOffset = Number(zip.readBigUInt64LE(eocdOffset - 20 + 8));
    expect(zip.readUInt32LE(zip64EocdOffset)).toBe(0x06064b50);

    // Reader round-trip — every entry returns intact regardless of
    // the ZIP64 framing.
    const entries = readZip(zip);
    expect(entries.map((e) => e.name)).toEqual([
      'manifest.json',
      'rows.ndjson',
    ]);
    expect(entries[0]!.data.toString('utf8')).toBe('{"v":1}');
    expect(entries[1]!.data.toString('utf8')).toBe('row-1\nrow-2\n');
  });

  it('forceZip64 LFH version-needed is 4.5 (45) per APPNOTE 4.5', () => {
    const zip = writeZip(
      [{ name: 'f', data: Buffer.from('x', 'utf8') }],
      { forceZip64: true },
    );
    // Local file header: signature at offset 0, version-needed at +4.
    expect(zip.readUInt32LE(0)).toBe(0x04034b50);
    expect(zip.readUInt16LE(4)).toBe(45);
  });

  it('reader rejects classic EOCD with sentinel but missing ZIP64 locator', () => {
    // Build a valid small archive then corrupt its classic EOCD so
    // it falsely claims ZIP64 sentinels without a locator. This is
    // the "ZIP64 promised, ZIP64 missing" failure mode and the
    // reader must reject rather than silently mis-read.
    const zip = writeZip([
      { name: 'a', data: Buffer.from('1', 'utf8') },
    ]);
    const corrupted = Buffer.from(zip);
    const eocdOffset = corrupted.length - 22;
    // Plant the sentinel on the cdOffset field.
    corrupted.writeUInt32LE(0xffffffff, eocdOffset + 16);
    expect(() => readZip(corrupted)).toThrow(ZipReadError);
  });

  it('reader tolerates unknown extra fields interleaved with ZIP64', () => {
    // Build a ZIP64 archive then splice an unknown extra-field record
    // (header ID 0xCAFE) into the central directory's extra region
    // BEFORE the ZIP64 extra. Per APPNOTE 4.5.1 readers MUST skip
    // unknown IDs by their declared size; the ZIP64 promotion must
    // still succeed.
    const original = writeZip(
      [{ name: 'x.txt', data: Buffer.from('payload', 'utf8') }],
      { forceZip64: true },
    );

    // The central directory begins right after all LFH+name+extra+data
    // sections. The locator stores its offset; we can find it by
    // reading the ZIP64 EOCD record.
    const eocdOffset = original.length - 22;
    const zip64EocdOffset = Number(
      original.readBigUInt64LE(eocdOffset - 20 + 8),
    );
    const cdOffset = Number(original.readBigUInt64LE(zip64EocdOffset + 48));

    // First CDH entry — read its extra-length, then splice 8 bytes
    // of unknown extra in FRONT of the existing extra payload, and
    // bump the extra-length by 8.
    const cdhExtraLenOffset = cdOffset + 30;
    const cdhNameLen = original.readUInt16LE(cdOffset + 28);
    const oldExtraLen = original.readUInt16LE(cdhExtraLenOffset);
    const cdhExtraStart = cdOffset + 46 + cdhNameLen;

    const unknown = Buffer.alloc(8);
    unknown.writeUInt16LE(0xcafe, 0); // unknown header id
    unknown.writeUInt16LE(4, 2); // 4 bytes of payload
    unknown.writeUInt32LE(0xdeadbeef, 4);

    // Splice: [..cdhExtraStart] + unknown + [cdhExtraStart..end]
    const head = original.subarray(0, cdhExtraStart);
    const tail = original.subarray(cdhExtraStart);
    const spliced = Buffer.concat([head, unknown, tail]);
    spliced.writeUInt16LE(oldExtraLen + 8, cdhExtraLenOffset);

    // The ZIP64 EOCD's cdSize and any downstream offset references
    // would also need adjustment in a real archive, but the reader
    // only uses cdSize to bounds-check against the buffer length —
    // since our splice GREW the buffer, the bounds check still holds
    // and the central directory walk reads the spliced unknown extra
    // first, skips it by size, then finds and promotes the ZIP64
    // extra. The locator's pointer to the ZIP64 EOCD also drifts by
    // +8 bytes (we inserted bytes BEFORE the EOCD), so we need to
    // rewrite the locator. Same for the classic EOCD's cdOffset
    // sentinel — but that's already 0xFFFFFFFF, so it stays.
    const newEocdOffset = spliced.length - 22;
    const newLocatorOffset = newEocdOffset - 20;
    spliced.writeBigUInt64LE(
      BigInt(zip64EocdOffset + 8),
      newLocatorOffset + 8,
    );
    // Update the ZIP64 EOCD's cdSize and the locator's count of
    // central dir entries (cdSize grew by 8 because we appended 8
    // bytes inside the CD).
    spliced.writeBigUInt64LE(
      original.readBigUInt64LE(zip64EocdOffset + 40) + 8n,
      zip64EocdOffset + 8 + 40,
    );

    const entries = readZip(spliced);
    expect(entries).toHaveLength(1);
    expect(entries[0]!.name).toBe('x.txt');
    expect(entries[0]!.data.toString('utf8')).toBe('payload');
  });
});
