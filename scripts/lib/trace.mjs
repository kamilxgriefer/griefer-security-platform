/**
 * Trace a binary mask into SVG path data.
 *
 * The approved GRIEFER mark exists only as raster artwork. Rather than
 * approximate it with hand-fitted arcs — which drifts from the thing that was
 * actually approved — this walks the ink boundary and emits real polygonal
 * contours. The output is genuine vector geometry derived from the source, not
 * a bitmap wrapped in an <svg> element.
 *
 * Deterministic: the same mask always produces the same contours in the same
 * order, so regenerating the assets does not churn the committed SVGs.
 */

/**
 * traceContours walks every boundary in a binary mask using Moore neighbour
 * following, returning closed rings in pixel coordinates.
 *
 * Both outer boundaries and holes are returned. They are distinguished by
 * winding, which is what lets an even-odd fill render counters — the hole in a
 * G, the dark field inside the shield — without any extra bookkeeping.
 */
export function traceContours(mask, width, height) {
  const at = (x, y) => (x < 0 || y < 0 || x >= width || y >= height ? 0 : mask[y * width + x]);
  const seen = new Uint8Array(width * height);
  const contours = [];

  // Clockwise neighbour offsets, starting due west.
  const NEIGHBOURS = [
    [-1, 0], [-1, -1], [0, -1], [1, -1],
    [1, 0], [1, 1], [0, 1], [-1, 1],
  ];

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      if (!at(x, y)) continue;
      // A boundary pixel is ink with a background pixel to its west.
      if (at(x - 1, y)) continue;
      if (seen[y * width + x]) continue;

      const ring = [];
      let cx = x;
      let cy = y;
      let dir = 0;
      const startX = x;
      const startY = y;
      let guard = 0;
      const limit = width * height * 8;

      do {
        ring.push([cx, cy]);
        seen[cy * width + cx] = 1;

        let found = false;
        // Resume the search just behind the direction we arrived from, which
        // keeps the walk hugging the boundary instead of cutting corners.
        for (let k = 0; k < 8; k++) {
          const d = (dir + 6 + k) % 8;
          const [dx, dy] = NEIGHBOURS[d];
          const nx = cx + dx;
          const ny = cy + dy;
          if (at(nx, ny)) {
            cx = nx;
            cy = ny;
            dir = d;
            found = true;
            break;
          }
        }
        if (!found) break; // isolated pixel
        guard++;
      } while ((cx !== startX || cy !== startY) && guard < limit);

      if (ring.length > 8) contours.push(ring);
    }
  }
  return contours;
}

/**
 * simplify reduces a ring with Ramer–Douglas–Peucker.
 *
 * epsilon is in source pixels. Too small and the SVG carries thousands of
 * points describing anti-aliasing noise; too large and curves visibly facet.
 */
export function simplify(points, epsilon) {
  if (points.length < 3) return points;

  const distance = (p, a, b) => {
    const [px, py] = p;
    const [ax, ay] = a;
    const [bx, by] = b;
    const dx = bx - ax;
    const dy = by - ay;
    const len = dx * dx + dy * dy;
    if (len === 0) return Math.hypot(px - ax, py - ay);
    let t = ((px - ax) * dx + (py - ay) * dy) / len;
    t = Math.max(0, Math.min(1, t));
    return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
  };

  const keep = new Uint8Array(points.length);
  keep[0] = 1;
  keep[points.length - 1] = 1;
  const stack = [[0, points.length - 1]];

  while (stack.length) {
    const [first, last] = stack.pop();
    let maxDist = 0;
    let index = -1;
    for (let i = first + 1; i < last; i++) {
      const d = distance(points[i], points[first], points[last]);
      if (d > maxDist) {
        maxDist = d;
        index = i;
      }
    }
    if (maxDist > epsilon && index !== -1) {
      keep[index] = 1;
      stack.push([first, index], [index, last]);
    }
  }
  return points.filter((_, i) => keep[i]);
}

/**
 * smoothToPath converts a simplified ring into a path with quadratic segments.
 *
 * Corner-to-corner lines would faceting a shape this round; running a quadratic
 * through each vertex's midpoints rounds it back without inventing detail the
 * source does not have.
 */
export function smoothToPath(points, transform, precision = 2) {
  const t = (p) => {
    const [x, y] = transform(p[0], p[1]);
    return [Number(x.toFixed(precision)), Number(y.toFixed(precision))];
  };
  const pts = points.map(t);
  if (pts.length < 3) return "";

  const mid = (a, b) => [
    Number(((a[0] + b[0]) / 2).toFixed(precision)),
    Number(((a[1] + b[1]) / 2).toFixed(precision)),
  ];

  const first = mid(pts[pts.length - 1], pts[0]);
  const parts = [`M ${first[0]} ${first[1]}`];
  for (let i = 0; i < pts.length; i++) {
    const current = pts[i];
    const next = pts[(i + 1) % pts.length];
    const m = mid(current, next);
    parts.push(`Q ${current[0]} ${current[1]} ${m[0]} ${m[1]}`);
  }
  parts.push("Z");
  return parts.join(" ");
}

/** dilate grows a mask by radius pixels, used to thicken the small variant. */
export function dilate(mask, width, height, radius) {
  if (radius <= 0) return mask;
  const out = new Uint8Array(mask.length);
  const r2 = radius * radius;
  const offsets = [];
  for (let dy = -radius; dy <= radius; dy++) {
    for (let dx = -radius; dx <= radius; dx++) {
      if (dx * dx + dy * dy <= r2) offsets.push([dx, dy]);
    }
  }
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      if (!mask[y * width + x]) continue;
      for (const [dx, dy] of offsets) {
        const nx = x + dx;
        const ny = y + dy;
        if (nx >= 0 && ny >= 0 && nx < width && ny < height) out[ny * width + nx] = 1;
      }
    }
  }
  return out;
}
