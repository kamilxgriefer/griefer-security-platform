/**
 * Strip private and non-essential ancillary chunks from a PNG.
 *
 * The approved source carries a `caBX` chunk — a private ancillary chunk
 * written by the tool that produced it. It is legal PNG, and `file` and macOS
 * read it happily, but libvips refuses the image outright with "unsupported
 * image format".
 *
 * Removing the chunk is byte surgery, not a re-encode: the IDAT stream is
 * copied verbatim, so the decoded pixels are bit-identical to the original.
 * The original file is never touched.
 */

import { readFileSync } from "node:fs";

const SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

/**
 * Chunks worth keeping. Critical chunks are mandatory; the ancillary ones
 * listed here carry colour and resolution information a decoder should honour.
 * Anything else is dropped.
 */
const KEEP = new Set([
  "IHDR", "PLTE", "IDAT", "IEND", // critical
  "tRNS", "gAMA", "cHRM", "sRGB", "iCCP", "pHYs", // colour and resolution
]);

/** normalizePng returns a PNG buffer containing only recognised chunks. */
export function normalizePng(buffer) {
  if (!buffer.subarray(0, 8).equals(SIGNATURE)) {
    throw new Error("not a PNG: signature mismatch");
  }

  const kept = [SIGNATURE];
  const dropped = [];
  let offset = 8;

  while (offset + 8 <= buffer.length) {
    const length = buffer.readUInt32BE(offset);
    const type = buffer.subarray(offset + 4, offset + 8).toString("latin1");
    const end = offset + 12 + length; // length + type + data + CRC
    if (end > buffer.length) {
      throw new Error(`truncated PNG: chunk ${type} claims ${length} bytes`);
    }

    if (KEEP.has(type)) {
      kept.push(buffer.subarray(offset, end));
    } else {
      dropped.push({ type, length });
    }

    offset = end;
    if (type === "IEND") break;
  }

  return { png: Buffer.concat(kept), dropped };
}

/** normalizePngFile reads path and returns a cleaned buffer. */
export function normalizePngFile(path) {
  return normalizePng(readFileSync(path));
}
