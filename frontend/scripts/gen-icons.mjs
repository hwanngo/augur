// Generate all PWA / favicon icons from public/augur-mark.svg.
// Run: pnpm exec node scripts/gen-icons.mjs   (re-run if the source mark changes)
import sharp from 'sharp';
import pngToIco from 'png-to-ico';
import { writeFileSync, copyFileSync } from 'node:fs';

const SRC = 'public/augur-mark.svg';
const DARK = { r: 0x0d, g: 0x11, b: 0x17, alpha: 1 };
const CLEAR = { r: 0, g: 0, b: 0, alpha: 0 };

/** Rasterize the shield mark to size×size (transparent), crisp via high density. */
async function shield(size) {
  return sharp(SRC, { density: 512 })
    .resize(size, size, { fit: 'contain', background: CLEAR })
    .png()
    .toBuffer();
}

/** Compose the shield (at `coverage` of the canvas) centered on a canvas of `bg`. */
async function icon(out, size, coverage, bg) {
  const inner = Math.round(size * coverage);
  const buf = await sharp({ create: { width: size, height: size, channels: 4, background: bg } })
    .composite([{ input: await shield(inner), gravity: 'center' }])
    .png()
    .toBuffer();
  writeFileSync(`public/${out}`, buf);
  console.log('wrote', out, `${size}px`);
}

// "any" icons — transparent background, shield ~82%
await icon('pwa-192x192.png', 192, 0.82, CLEAR);
await icon('pwa-512x512.png', 512, 0.82, CLEAR);
// "maskable" — full-bleed dark, shield inside the 80% safe zone
await icon('maskable-192x192.png', 192, 0.72, DARK);
await icon('maskable-512x512.png', 512, 0.72, DARK);
// iOS apple-touch-icon — opaque dark, no transparency
await icon('apple-touch-icon.png', 180, 0.70, DARK);

// favicons — vector + multi-res .ico on a dark tile
copyFileSync(SRC, 'public/favicon.svg');
const favBufs = [];
for (const s of [16, 32, 48]) {
  favBufs.push(
    await sharp({ create: { width: s, height: s, channels: 4, background: DARK } })
      .composite([{ input: await shield(Math.round(s * 0.8)), gravity: 'center' }])
      .png()
      .toBuffer(),
  );
}
writeFileSync('public/favicon.ico', await pngToIco(favBufs));
console.log('wrote favicon.svg + favicon.ico');
