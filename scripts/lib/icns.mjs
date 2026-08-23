/**
 * Minimal ICNS encoder.
 *
 * macOS ships `iconutil`, which does this — but only on macOS, which would
 * make the asset pipeline produce different output depending on where it runs.
 * The format is a magic number, a length, and a sequence of typed chunks, so
 * encoding it directly keeps the build deterministic and portable.
 *
 * Only PNG-carrying chunk types are emitted. The legacy packbits types are
 * unnecessary on any macOS that could run this project.
 */

const MAGIC = "icns";
const CHUNK_HEADER_BYTES = 8;

/**
 * Chunk types, mapped to the pixel dimensions they carry.
 *
 * The @2x types describe the same logical size at double resolution; macOS
 * picks between them by display scale, so both are supplied.
 */
export const ICNS_TYPES = [
  { type: "icp4", size: 16 },
  { type: "icp5", size: 32 },
  { type: "icp6", size: 64 },
  { type: "ic07", size: 128 },
  { type: "ic08", size: 256 },
  { type: "ic09", size: 512 },
  { type: "ic10", size: 1024 }, // 512@2x
  { type: "ic11", size: 32 }, //  16@2x
  { type: "ic12", size: 64 }, //  32@2x
  { type: "ic13", size: 256 }, // 128@2x
  { type: "ic14", size: 512 }, // 256@2x
];

/** encodeIcns packs { type, png } entries into an .icns container. */
export function encodeIcns(entries) {
  if (entries.length === 0) throw new Error("icns: at least one image is required");

  const chunks = entries.map(({ type, png }) => {
    if (type.length !== 4) throw new Error(`icns: type ${type} must be 4 characters`);
    const header = Buffer.alloc(CHUNK_HEADER_BYTES);
    header.write(type, 0, 4, "latin1");
    // The length field counts the header as well as the payload.
    header.writeUInt32BE(CHUNK_HEADER_BYTES + png.length, 4);
    return Buffer.concat([header, png]);
  });

  const body = Buffer.concat(chunks);
  const header = Buffer.alloc(CHUNK_HEADER_BYTES);
  header.write(MAGIC, 0, 4, "latin1");
  header.writeUInt32BE(CHUNK_HEADER_BYTES + body.length, 4);

  return Buffer.concat([header, body]);
}
