# Logo assets

`logo.png` is the project mark: `WEIRVERN` beneath a dragon rendered as circuit
traces, whose body doubles as a siphon with water passing through it. The name
decomposes into three legitimate reads — **siphon** (a conduit the flow is drawn
through), **wyvern** (the dragon), and "on the wire" (the circuit work) — and the image
carries all three.

## Files

| Path | Purpose |
|---|---|
| `logo.png` | The source mark, 490×480, for the README header and social previews |
| `favicon/favicon-{16,32,48,64,128,180,192,512}.png` | Pre-rendered sizes so nothing upscales |
| `favicon/favicon.ico` | Multi-resolution icon (16/32/48) for browsers and bookmarks |

## Two deliberate properties

**The favicons are cropped to the mark only, without the wordmark.** Downscaling
the full canvas to 16px squeezes the wordmark in as well, and it degrades into
illegible text artifacts that read as visual noise. The crop gives the dragon a
larger share of those 16 pixels. `docs/logo.png` keeps the wordmark for large
contexts; the favicons drop it for small ones.

**The favicons are opaque, not transparent.** The background is a dark navy with
a faint hexagonal texture, not a flat colour, so a colour-key would eat into the
dragon's glow at the edges. Attempting it retained only ~20% of pixels as opaque
— visibly degrading the artwork — so the background is kept instead. This is
correct on the dark surfaces the project actually appears on (GitHub dark mode,
a terminal, a dark dashboard); on a light browser theme the favicon reads as a
dark tile, which is the honest trade.

## If you ever want transparency or a single flat colour

That needs a **vector** redraw, not image processing — a raster with a baked
textured background cannot be cleanly keyed. A redraw would also let the mark
work at 16px without the detail loss visible in the smallest favicon.

## Regenerating the favicons

After replacing `logo.png`, from the repository root:

```bash
# Crop to the mark (drops the wordmark; source is 490x480, mark occupies the top ~62%)
magick docs/logo.png -crop 100%x62%+0+0 +repage /tmp/mark_only.png

rm -rf docs/favicon && mkdir -p docs/favicon
for s in 16 32 48 64 128 180 192 512; do
  magick /tmp/mark_only.png -resize ${s}x${s} -background none \
         -gravity center -extent ${s}x${s} docs/favicon/favicon-${s}.png
done
magick docs/favicon/favicon-16.png docs/favicon/favicon-32.png \
       docs/favicon/favicon-48.png docs/favicon/favicon.ico
```

Then run `pytest tests/test_logo.py` — it asserts the sizes exist, that the
`.ico` really holds multiple resolutions, and that the source is still the
largest asset.
