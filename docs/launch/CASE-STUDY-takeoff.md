# How comparable projects took off - and Filament's takeoff plan

A case-study-driven growth playbook. Researched 2026-06-11 from primary sources
(GitHub API, the HN/Algolia API, maintainer interviews, and the tools' own
blogs). This is the *analysis* behind the tactical drafts already in
`docs/launch/` (Show HN, Reddit, AlternativeTo, awesome-selfhosted) and the
`docs/launch-checklist.md` - read this for the *why*, read those for the *paste*.

Positioning rule throughout: always **"Filament file sharing"**, never bare
"filament" (3D-printing collision).

---

## TL;DR

1. **None of the analogues broke out from their own launch post.** Snapdrop's
   Show HN got 6 points and died; its 527-point HN moment came **5 years later,
   submitted by someone else**. LocalSend's takeoff was a **Chinese software
   blog**, not Reddit/HN. croc has **no big Show HN at all**. The lesson is not
   "nail the launch" - it's **build the compounding loop that lets word-of-mouth
   re-fire for years**.
2. **The durable engine in this category is the shareable artifact + the
   "default recommendation" loop**, not a one-day spike. Snapdrop/PairDrop grow
   because the product *is a URL you tell someone*; Syncthing/ngrok grow because
   they're the reflexive answer in every relevant thread and tutorial.
3. **Filament's real moat survived the one event that should scare us.** In
   Nov 2025 Google shipped native **Quick Share ↔ AirDrop** interop (Pixel 10),
   expanding through 2026 to Samsung/Xiaomi/OPPO/vivo/Honor/OnePlus flagships.
   That **validates the demand and partly solves the flagship-phone↔phone slice**
   - but it's phone-only, recent-flagship-only, no headless/server, no
   browser-only device, no Linux, no self-host, no route visibility. **Re-aim off
   "AirDrop for Android↔iPhone" and onto the gaps the OS will never cover.**

---

## Part 1 - The case studies (what actually happened)

### LocalSend - the closest analogue, and the most important lesson

- Flutter app, MIT, repo created **2022-12-16**. Tagline everyone repeats:
  **"an open-source cross-platform alternative to AirDrop."**
- **The takeoff was NOT Reddit or HN.** A Chinese software blog, **appinn.com
  (小众软件)**, featured it as its "first pick of the Year of the Rabbit" in
  **late Jan 2023** - on a ~6-week-old repo. The spike was so steep that GitHub
  issue **#62 "Did you buy GitHub stars?"** was opened accusing the maintainer of
  buying ~18k stars (he hadn't). The maintainer: *"I shared LocalSend on a
  Chinese website, maybe that's why the stars grow."*
- **HN was a recurring amplifier, not the origin.** Multiple early HN posts (Jan,
  Feb, May 2023) got near-zero. The hits came **after** it was already growing:
  563 pts (Oct 2023), 447 pts (Mar 2024), **923 pts (Apr 2026, its biggest)**.
- **Star trajectory:** ~11k (Jun 2023) → 26k (Dec 2023) → 34k (Apr 2024) →
  55k (Jan 2025) → **~83k (Jun 2026).**
- **The durable engine was consumer app-store distribution, not GitHub.** Shipped
  to App Store + Play Store **within ~3 weeks of starting**, Windows soon after.
  The maintainer is explicit: *download counts*, not stars, were the real signal;
  *"99% of consumers don't care how many stars the repo has."* Today it's in
  F-Droid, Flathub, winget, Homebrew, Scoop, Snap, Chocolatey + both app stores.
- **Filament takeaways:** (a) the **self-describing "open-source AirDrop
  alternative" hook is free SEO** that re-seeds blog/HN coverage for years;
  (b) **distribution = being installable everywhere people already look**
  (package managers + app stores), not a repo link; (c) **one well-placed feature
  in the right community can outrun a "perfect" HN launch** - go where the
  enthusiasts already congregate.
  > Sources: github.com/localsend/localsend/issues/62 · console.substack.com/p/console-181 · HN Algolia · Wayback star snapshots.

### Snapdrop & PairDrop - "the app is a URL" is the whole growth model

- Snapdrop (Robin Linus), repo **2015-12-18**, framing **"AirDrop for the web."**
  Its **own Show HN (2015-12-25) got 6 points and flopped.** The breakout came
  later: **527 pts, 144 comments on 2020-12-24, submitted by a USER, not the
  author.** ~19.7k stars; funded by GitHub Sponsors for server costs (no VC).
- **Snapdrop later degraded:** acquired by **LimeWire** (~2025), stopped being
  local/P2P/private (cloud routing, AI feature, paywalls), and got
  **flagged as badware by uBlock Origin's uAssets**. This is a cautionary tale
  about who ends up owning the canonical URL.
- **PairDrop (schlagmichdoch), repo 2023-01-07**, "Fork of Snapdrop," **actively
  maintained**, ~10.5k stars. Added what Filament also has: **transfer over the
  internet, pairing via 6-digit code/QR persisting across sessions, temporary
  public rooms.** It grew through **repeated small organic HN re-submissions**
  (often by other users) + the **self-hosting community** (LinuxServer.io Docker
  image, r/selfhosted roundups). When the repo briefly vanished in Mar 2024, the
  panic thread hit **102 pts** - evidence of a real dependent user base.
- **The compounding loop is structural:** the onboarding *is* "go to
  pairdrop.net." Traffic is **~68% direct** (people typing/bookmarking/telling
  others the URL) + **~24% from Google**. Every successful transfer **teaches a
  second person the URL** - virality is built into the product shape.
- **Filament takeaways:** (a) **the share is the URL** - make
  `filament.autumated.com` trivially memorable/tellable and the in-person
  "what's the link?" moment frictionless; (b) **own your canonical URL and
  privacy promise** so you can't become the cautionary LimeWire story; (c) you
  don't need a hero launch - **a steady drip of organic HN/Reddit re-posts** (by
  you *and* by users) compounds.
  > Sources: HN 25524472, 43348627, 39665668 · github.com/schlagmichdoch/PairDrop · uBlockOrigin/uAssets#27172 · Similarweb.

### magic-wormhole & croc - the dev word-of-mouth hook

- **magic-wormhole (Brian Warner):** repo 2015, ~22.7k stars. The thing that
  spread it was the **PyCon 2016 talk** + the **human-speakable code**:
  `wormhole send` / `wormhole receive 4-purple-sausages`. You can *yell the code
  across a room*; PAKE turns the weak words into a strong key. HN: 744 pts
  (2017), **816 pts (2024, its biggest)** - repeatedly re-fired over a decade.
- **croc (schollz):** repo 2017, **~35.2k stars - it overtook wormhole.** Why?
  schollz's own stated motivation: send a 3GB file to a friend who **"has a
  Windows computer and is not comfortable using a terminal"** → receiving had to
  be "download the executable and double-click." croc's edges over wormhole:
  **single static cross-platform binary** (no Python install), `croc send`
  one-liner, **resumable transfers**, folders, LAN discovery. Notably **croc has
  no big "Show HN"** - it grew on the repo, package managers, and being the
  recommended answer (HN 300 pts in 2023 was a re-submission).
- **The security arc that built trust:** croc originally used SHA256, not PAKE;
  issue **#71 (2018)** critiqued it against wormhole's PAKE; croc **rewrote to
  PAKE in v6.0.0 (2019)**. Responding to a credible critique *publicly and
  quickly* became part of the trust story.
- **Filament takeaways:** (a) Filament already has the **speakable-code hook**
  *and* a stronger one - **the receiver needs nothing installed at all**, beating
  even croc's "download a binary"; (b) **"resumable, survives restarts" is a
  proven star-driver** - Filament has it; say it loudly; (c) lean into the
  **honest engineering-failure-modes writeup** (`docs/resilience.md`) - this
  audience rewards candor and verifiable artifacts.
  > Sources: schollz.com/posts/croc · croc#71 · croc v6.0.0 · HN 14649727, 41275920, 37619151 · GitHub API.

### Syncthing, Tailscale, ngrok - the "become the default" distribution engine

- **Syncthing:** grew as **"the open-source BitTorrent Sync alternative"** (rode a
  trust backlash against a proprietary incumbent), seeded by **Steve Gibson on
  Security Now! (2014+)**, and is **in every distro's native repos** (Fedora,
  Debian/Ubuntu, Arch + an official APT repo). ~85k stars. It's the **reflexive
  "just use Syncthing"** answer in r/selfhosted - being free + open + one
  `apt install` away makes it *safe to recommend*, and each recommendation
  compounds.
- **Tailscale:** explicitly **product-led / word-of-mouth** growth. The
  documented path: **unlimited free tier for personal use** → home users tell
  their teams → teams adopt → enterprise pays. They literally say users *"pay us
  by talking about us."* **500k+ weekly active users; paid business clients
  5,000 (Mar 2024) → 10,000 (Jan 2025).** Reddit + blog content rank in search
  and feed the top of the funnel.
- **ngrok:** the **one-command hook** (`ngrok http 3000` → public URL to
  localhost) was the distribution. Free-tier-as-distribution made it the
  **default recommendation embedded in *other products'* getting-started docs**
  (Stripe, Twilio, GitHub, Slack webhooks) - every webhook quickstart became an
  ngrok ad. Bootstrapped to ~**5M users before any funding.**
- **The transferable mechanic (all three):** **free is the distribution channel,
  not a marketing cost.** The loop: low/zero friction to first success → it works
  and is *safe to recommend* (free/open, nobody gets burned) → it gets written
  into tutorials, Reddit threads, awesome-lists, and other products' docs →
  those rank in search and seed the next user → repeat. Each cycle **raises the
  bar for any competitor**, because displacing "the default everyone recommends"
  is far harder than the original adoption.
  > Sources: tailscale.com/blog/free-plan · betakit.com (10k clients) · ngrok.com/about · HN 5946981 · en.wikipedia.org/wiki/Syncthing · awesome-selfhosted.

---

## Part 2 - The 2026 channel reality (so we don't fight the last war)

- **Show HN is a spike, not a flywheel.** Median Show HN scores **2 points**;
  **50 pts = top 6%**, **250+ = top 1%**; **28,302 Show HN posts in 2025**
  (volume tripled in a decade). **Early velocity beats totals** - ~8-10 genuine
  upvotes + 2-3 comments in the **first 30-60 min** is decisive. And the payoff
  is modest and short: HN points↔stars correlate only **r≈0.29**; each upvote ≈
  **1.4 stars**; **~92% of the bump is gone in 48h.** HN is still the **biggest
  single-day dev-tool referrer**, but treat it as **one shot that seeds the
  loop**, not the strategy.
- **Reddit converts when you're a participant, not a poster.** Best-fit subs for
  Filament: **r/selfhosted** (~650k weekly), **r/coolgithubprojects**,
  **r/opensource**, plus r/webdev, r/sideproject, r/androidapps, r/fossdroid.
  Governing rule: Reddit's **10% self-promo rule** + per-sub promo days
  ("Self-Promotion Sunday"). Lead with a **GIF**, frame as "I built X to solve
  Y," post to **2-3 best-fit subs**, and **stay and answer**.
- **Product Hunt = amplifier/backlink, not an engine.** Honest consensus:
  *"doesn't really work, but you should still launch on it"* for the credibility
  badge + non-dev reach. Launch **12:01am PT**. For a CLI/p2p tool, HN+Reddit
  out-deliver PH on relevant users.
- **GitHub Trending rewards velocity vs. your own baseline** - fire HN + Reddit +
  PH the **same day** to trip it. Add **repo topics**; earn the **first 50+ stars
  organically** (a documented fake-star economy has made stars partly distrusted).
- **awesome-selfhosted has a hard gate:** project must be **first *released* >4
  months ago** (clock starts at a tagged release), FOSS, actively maintained;
  **LLM-generated PRs that ignore guidelines get banned.** (Already handled  - 
  v1.0.0 was cut 2026-06-06 and a routine is scheduled to open the PR
  2026-10-07; see `docs/launch-checklist.md`.)
- **The SEO long-tail is real but MOVED.** "AirDrop for Android / Android↔iPhone"
  intent is large and evergreen *but partially solved by the OS now* (see Part 3).
  Capture it with **comparison/landing pages, FAQ pages (featured snippets),
  /about problem-narrative, structured data** - re-aimed at the still-unserved
  gaps.

---

## Part 3 - The strategic pivot: what Google's Quick Share↔AirDrop changes

**The event:** Nov 2025, Google shipped **native Quick Share ↔ AirDrop** (Pixel
10); through 2026 it expanded to **Samsung, Xiaomi, OPPO, vivo, Honor, OnePlus**
flagships (Pixel 9/8a, Galaxy S26 first non-Pixel, June 2026 feature drop).
Encrypted, P2P over Wi-Fi/Bluetooth. *Primary source: blog.google; corroborated
by MacRumors, AppleInsider, 9to5Google.*

**What it solved:** the headline "Android↔iPhone has no AirDrop" pain - **for
recent flagship phones, phone-to-phone, in person.**

**What it did NOT solve (Filament's actual territory):**
- **Older / mid-range / unsupported devices** - no timeline announced.
- **Phone ↔ PC, and iPhone ↔ Windows / Linux** - the OS feature is phone-to-phone.
- **Headless / servers** - a Linux box with no GUI can't run Quick Share;
  `filament send` on the box → a browser on the phone still has no rival.
- **Browser-only / "nothing installed" device** - the OS feature needs the OS
  feature on *both* ends; Filament's receiver needs only a URL.
- **Self-hosted / no-account / route-visible** - privacy/control story untouched.

**Conclusion:** the OS move is **tailwind, not headwind** - it spent Google's
marketing budget teaching the world that cross-device P2P sharing should "just
work," then left every non-flagship, cross-form-factor, headless, and
privacy-controlled case on the table. **Stop competing for the slice the OS
took; own the larger slice it can't reach.**

---

## Part 4 - Filament's positioning (the 2-3 angles that will resonate)

Ranked by defensibility against the 2026 landscape:

1. **"The receiver installs nothing - any device, even a headless server."**
   *This is the single strongest, most unique line.* Beats croc ("download a
   binary"), beats Quick Share (needs the OS feature on both ends), beats
   LocalSend (an app on both ends). The vivid version:
   > *"Send a file from your headless Linux box to your wife's iPhone. She opens
   > a link and taps accept. Nothing installed on her phone, no account, no app."*
   This is the demo that makes people share it.

2. **"See the route your bytes take - LAN / direct / relay."** No competitor
   surfaces this. It's both a **trust feature** (you can prove nothing was
   uploaded) and a **debugging feature**. This is the HN-bait angle - the same
   "I haven't seen other tools do this" hook the existing Show HN draft leads
   with. Keep it as the *technical* headline.

3. **"Resumable, content-verified, self-hostable - the engineering is
   documented failure-by-failure."** croc/wormhole proved resume + a candid
   writeup drive stars. Filament's `docs/resilience.md` + `docs/cli-resilience.md`
   (every fix gated by a test) is a credibility asset most projects can't match.

**Channel positioning (already in the checklist, reaffirmed):**
- **Consumer framing:** "Send files between any phone and any computer - no app,
  no account, no cloud." (Re-aimed off the now-OS-solved Android↔iPhone phrasing
  toward **phone↔PC / iPhone↔Windows-Linux / older-device / privacy**.)
- **Technical framing:** "Self-hosted, route-transparent P2P file drop with
  resumable transfers; the other end needs nothing installed."

---

## Part 5 - The sequenced launch plan

**Phase A - pre-launch foundations (mostly done; verify):**
- Working repo with a great README + a **15s two-device demo GIF** above the fold
  (the "no clear one-liner / launch to silence" anti-patterns are top killers).
- The **failure-modes blog post** published on Abdk4Moura.github.io first, so the
  HN first comment can link a real artifact.
- Landing/FAQ pages re-aimed at the **post-Quick-Share gaps** (phone↔PC,
  iPhone↔Windows/Linux, headless, privacy/local-only). Add SoftwareApplication +
  FAQ structured data. (Phase 0 SEO is already done per the checklist.)
- Earn the **first 50+ stars organically** (share in a couple of Discords/dev
  circles) *before* the public push, so Trending has a baseline to spike from.

**Phase B - the coordinated single day (trip GitHub Trending):**
- **Show HN** in a low-competition window (the data's robust signal: post just
  before a working audience wakes - practitioner pick **Tue-Thu 8-10am PT**;
  the 188k-post dataset favors **Sun eve / Mon 00:00 UTC**; pick one, don't
  agonize). Lead with **route-transparency** (angle 2). **Maker first comment
  immediately**: ~60-word what/why + the one technical decision + an honest
  limitation + the failure-modes link. **Stay and answer for 2-3h.**
- **Same day:** post to **r/selfhosted** (self-host + route-visibility + no-cloud)
  and **r/coolgithubprojects**; tailor each, lead with the GIF, no cross-post
  spam. **Product Hunt** at 12:01am PT for the badge/backlink.
- The simultaneity is the point - a coordinated same-day spike is what trips
  **GitHub Trending**, which then seeds the next wave on its own.

**Phase C - the compounding loop (this is where the real growth is):**
- **Distribution everywhere people look:** you already have winget + Homebrew tap
  + `curl | sh`. Add/confirm **Scoop, Chocolatey, AUR, Nix, Flathub** for the CLI;
  pursue **F-Droid/Play/App Store** *only if* a thin mobile wrapper is ever worth
  it (LocalSend's lesson: app stores were *the* consumer engine - but that's a
  real commitment; the browser receiver already covers mobile zero-install).
- **awesome-selfhosted PR** (scheduled 2026-10-07) + other awesome-* lists
  (awesome-p2p, awesome-cli-apps, awesome-webrtc).
- **Be the default recommendation:** answer - genuinely, not spammily - standing
  threads on "send files phone↔PC," "AirDrop for Windows/Linux," "transfer
  between two computers." 5 genuinely-helpful answers > 50 drive-by links.
  This is the Syncthing/ngrok loop: every helpful answer ranks in search and
  seeds the next user.
- **Re-fire HN/Reddit periodically** the way wormhole/PairDrop/LocalSend did  - 
  a meaningful release or a new writeup is a legitimate re-submission, and these
  re-fires (often by *other users*) are where the multi-year compounding lives.
- **Content as SEO:** one solid writeup per quarter (the WebRTC-failure-modes
  post is the template) keeps long-tail traffic compounding.

---

## Part 6 - Leading indicators to watch

Stars are a *vanity* lagging metric (and partly distrusted post-fake-star-era).
Track these instead:
- **First-30-min HN velocity** on launch day (upvotes + comments) - the only
  thing that predicts front page.
- **Direct vs. search traffic split** to filament.autumated.com over time - the
  PairDrop tell: rising **direct** traffic = the word-of-mouth "tell them the
  URL" loop is working; rising **search** traffic = the SEO loop is working.
- **Returning unique senders/receivers** and **completed transfers** - the
  LocalSend lesson: *usage*, not stars, is the real signal.
- **"Recommended-by-someone-else" events** - unsolicited mentions in threads,
  awesome-list inclusions, other projects' docs linking you. This is the
  compounding loop made visible.
- **CLI install counts** per package manager (the dev-distribution proxy).

---

## Part 7 - Anti-patterns that kill these launches (avoid all)

- **Launching to silence** - no working repo / no README / no demo at announce.
- **No clear one-liner** - jargon over the plain "what + why."
- **Over-claiming** - hyping vision over the actual code destroys credibility,
  sometimes permanently. (Filament's honesty - documented limits, route badges
  including the unflattering `relayed` - is an *asset*; keep it.)
- **Drive-by promotion** - posting a link then vanishing; tanks HN and Reddit.
- **Wrong subreddit / breaking the 10% rule** - generic cross-posting gets pulled.
- **Defensive replies to criticism** - croc's lesson is the opposite: respond to
  a credible critique publicly, fix it, say so.
- **Treating the launch as the strategy** - every analogue's real growth was the
  *loop after* the launch, not the launch.
- **Losing control of the canonical URL/promise** - Snapdrop→LimeWire is the
  warning. Guard `filament.autumated.com` and the no-upload promise.

---

## Appendix - confidence & caveats

- **High confidence** (primary sources / APIs): all repo + release dates, star
  counts, HN points/dates, the Quick Share↔AirDrop interop facts, LocalSend's
  Chinese-blog origin + issue #62, Snapdrop's flopped Show HN + 2020 user-posted
  breakout + LimeWire degradation, croc's motivation quote + PAKE rewrite,
  Tailscale's paid-client counts + self-stated PLG, ngrok's one-command hook +
  webhook-tutorial ubiquity, awesome-selfhosted's 4-month rule, HN velocity/decay
  mechanics.
- **Medium / flagged:** exact best HN post time (datasets disagree - treat as a
  hypothesis, optimize for low competition); Snapdrop's "millions of monthly
  users" (secondary); Similarweb/Semrush traffic numbers (estimates); exact SEO
  keyword volumes (tools were gated - *direction* is well-evidenced, the numbers
  are not); Syncthing's "always recommended" pattern (real culturally, no single
  metric).
- **Don't assert without re-checking:** specific Reddit launch-thread upvotes for
  LocalSend/PairDrop (not found); awesome-* list entries for wormhole/croc
  (unverified).

Primary sources are linked inline per section above.
