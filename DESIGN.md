# DESIGN.md — Iskan Portal

## Identity
Iskan Portal — personal infra dashboard (ops tool, bukan landing). Dark-only, padat informasi, dipakai tiap hari untuk monitor VPS + kuota + services. Karakter: tenang tapi hidup, bukan neon, bukan steril.

## Palette (R-01, R-29)
- Base #09090b, Surface #18181b, Border #27272a — neutral gelap sebagai ground (alasan: dashboard lama dibuka mata tidak silau, kontras AA).
- Muted #a1a1aa, Text #f4f4f5 — hierarki teks (muted 7.76:1, text 18:1 di base = PASS AA).
- Accent #14b8a6 (teal) — SATU accent untuk aksi primer + state active (alasan: satu titik fokus per layar, bukan disebar).
- Fungsional: merah #ef4444 internet, biru #3b82f6 aplikasi, hijau #22c55e voice/telepon, amber #d97706 sms/malam — dipakai HANYA di donut + bar kuota agar kategori kebaca tanpa label panjang (alasan: kuota 3 provider 1 model, warna = kategori, bukan hiasan).
- Chart: sky #38bdf8 RAM, violet #a78bfa RX, amber #f59e0b power — beda domain (infra metrics), jadi tidak hitung ke palet kuota.
- Aurora: teal .9 / sky .8 / rose .65 opacity rendah blur60 — hanya background, tidak naik ke komponen.

## Typography (R-06)
- Sans: ui-sans-serif system stack, mono untuk angka/status (alasan: keterbacaan dense table + angka kuota tabular-nums, bukan estetika mono).
- Tidak ada monospace besar headline, tidak ada uppercase tracking ekstrem.

## Layout (R-05)
- Sidebar 240↔64 + mobile drawer, bukan template landing. Section order = kebutuhan ops: overview → task manager → kuota → services → terminal → embeds.
- Kuota 3 kolom proporsional lg:grid-cols-3, kartu flex-1 sama tinggi — variasi ritme datang dari konten (donut 130px vs list), bukan bento mosaic.

## Motion & Decoration (R-10, R-13, R-19)
- Aurora portal-drift-a 6s / b 7s / c 8s ease-in-out alternate + reduced-motion 12s (alasan: infra padat tabel butuh energi di belakang, warna hanya palet, opacity rendah agar kontras tetap AA).
- Backdrop-blur hanya di 3 titik: sidebar surface/60, overlay mobile, modal backdrop — tidak simultan di desktop (sidebar dan overlay tidak bareng), dose 1-2 efektif.
- Tidak ada glow di card/button/badge/icon sekaligus. Shadow hanya elevation ringan di sidebar mobile.

## Dials (Part 3)
Dial: ENERGY 2 / RHYTHM 2 / MOTION 2
- ENERGY 2: balanced (Stripe/Vercel) — alat harian, tidak berteriak, tidak mati.
- RHYTHM 2: konsisten dengan break — grid overview vs chart vs kuota 3-kolom vs embed.
- MOTION 2: scroll-reveal/transitions + aurora slow drift (alasan di atas). Hover states tetap utama, aurora satu-satunya loop.

## Liveliness Levers
- Focal: active nav + header action (Refresh/Cek) — satu accent teal.
- Hierarchical contrast: ukuran/tebal/warna dibeda sengaja (judul xs uppercase, angka lg semibold).
- Whitespace structural: p-2.5/3 sebagai scale, bukan sisa.
- Identity motif: status dot h-2 w-2 + border/gradient tipis kategori — diulang di overview, task manager, kuota.

## Notes
Dark-only keputusan produk (ops malam), bukan "dark looks tech" (R-21). Tidak ada light toggle karena tool internal.
