# Filament launch checklist

Owners: **C** = Claude (drafts/ships directly) · **A** = Abdul (account actions).
Drafts land in `docs/launch/` ready to paste.

## Phase 0 — Foundation ✅
- [x] On-page SEO: title/description/canonical, OG + Twitter cards, WebApplication JSON-LD (C)
- [x] Indexable `/about` + `/faq` pages with FAQPage structured data (C)
- [x] `robots.txt` + `sitemap.xml` (C)
- [x] GitHub topics + README live-link tagline (C)
- [x] Google Search Console verified, sitemap submitted (A)
- [x] Bing Webmaster Tools verified (A)

## Phase 1 — Assets (C drafts)
- [x] OG card image (1200×630) at `/og.png`, wired into `og:image` + `summary_large_image`
- [x] Show HN draft → `docs/launch/show-hn.md`
- [x] Blog post draft: "Eleven ways WebRTC file transfer fails (and the fixes)" → `docs/launch/blog-webrtc-failures.md`
- [x] AlternativeTo listing copy → `docs/launch/alternativeto.md`
- [x] r/selfhosted post draft → `docs/launch/reddit-selfhosted.md`
- [x] awesome-selfhosted entry prepared → `docs/launch/awesome-selfhosted.md`
- [x] MIT LICENSE added to the repo
- [x] **v1.0.0 release** cut (required: awesome-selfhosted needs a release ≥ 4 months old)

## Phase 2 — Launch (A executes, C's drafts in hand)
- [ ] Publish the blog post on Abdk4Moura.github.io (C can push after approval)
- [ ] Show HN — Tue–Thu, 8–10am ET; stay 2–3h for comments
- [ ] r/selfhosted post (different week than HN)
- [ ] AlternativeTo listing (alternative to Snapdrop / PairDrop / AirDrop / WeTransfer)
- [ ] awesome-selfhosted PR — **scheduled**: a remote routine ("Open awesome-selfhosted
      PR for Filament") fires 2026-10-07 09:00 UTC and opens the PR from the staged
      branch `Abdk4Moura/awesome-selfhosted-data@add-filament` (Oct 7, not Oct 6,
      for one day of buffer past the exactly-4-months mark; v1.0.0 released 2026-06-06).
      Manage at https://claude.ai/code/routines
- [ ] GSC: Request Indexing for `/`, `/about`, `/faq` (after OG image ships)

## Phase 3 — Evergreen (ongoing)
- [ ] 5 genuinely helpful answers on standing "AirDrop Android↔iPhone" threads (Reddit/SE)
- [ ] Demo GIF in README + `/about` (A records ~15s two-device transfer; C embeds)
- [ ] After 2 weeks: review GSC queries, extend `/faq` to match what people actually search

**Positioning per channel:** consumer = "AirDrop between Android and iPhone, in the browser";
technical = "self-hosted, route-transparent P2P file drop with resumable transfers".
**Naming rule:** always "Filament file sharing" — never bare "filament" (3D-printing collision).
