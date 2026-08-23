/**
 * Minimal ICO encoder.
 *
 * Written here rather than pulled in as a dependency: the format is a header
 * and a directory, PNG payloads are legal for every size Windows Vista and
 * later reads, and a security project gains nothing by adding a package to
 * concatenate a few hundred bytes.
 */

const DIRECTORY_ENTRY_BYTES = 16;
const HEADER_BYTES = 6;

/**
 * encodeIco packs PNG buffers into a multi-resolution .ico.
 *
 * images is [{ size, png }]. Sizes above 256 cannot be represented in the
 * directory — the width and height fields are a single byte each, where 0
 * means 256 — so they are rejected rather than silently truncated to a wrong
 * value.
 */
export function encodeIco(images) {
  if (images.length === 0) throw new Error("ico: at least one image is required");
  for (const { size } of images) {
    if (size < 1 || size > 256) {
      throw new Error(`ico: size ${size} is out of range; the directory stores 1..256`);
    }
  }

  const sorted = [...images].sort((a, b) => a.size - b.size);

  const header = Buffer.alloc(HEADER_BYTES);
  header.writeUInt16LE(0, 0); // reserved
  header.writeUInt16LE(1, 2); // 1 = icon
  header.writeUInt16LE(sorted.length, 4);

  const directory = Buffer.alloc(DIRECTORY_ENTRY_BYTES * sorted.length);
  let offset = HEADER_BYTES + directory.length;

  sorted.forEach(({ size, png }, index) => {
    const at = index * DIRECTORY_ENTRY_BYTES;
    // 256 is encoded as 0; every other size fits in a byte.
    directory.writeUInt8(size === 256 ? 0 : size, at);
    directory.writeUInt8(size === 256 ? 0 : size, at + 1);
    directory.writeUInt8(0, at + 2); // palette size, 0 for truecolour
    directory.writeUInt8(0, at + 3); // reserved
    directory.writeUInt16LE(1, at + 4); // colour planes
    directory.writeUInt16LE(32, at + 6); // bits per pixel
    directory.writeUInt32LE(png.length, at + 8);
    directory.writeUInt32LE(offset, at + 12);
    offset += png.length;
  });

  return Buffer.concat([header, directory, ...sorted.map((i) => i.png)]);
}
