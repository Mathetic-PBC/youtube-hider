# youtube-hider

YouTube as a search bar. No home feed, no Shorts, no "up next", no
suggestions, and everything you open is checked by a model running on your Mac
against what you said you come to YouTube for.

- **Home** is a single search box. Nothing else loads.
- **Search results** show results. Shorts shelves, "people also watched"
  shelves, ads and search suggestions are removed.
- **Watch pages** are the video, its title, the channel's name and the
  description. The recommendation column, end-of-video wall, autoplay,
  comments, avatar, subscriber count and subscribe button are removed, and
  the video takes the width they leave behind.
- **Every search, video, channel and playlist** is classified by a local
  model in about a quarter of a second, whether you searched for it, clicked
  it, or followed a link from somewhere else. What doesn't fit gets a
  "Not approved" page with the model's reason and how sure it was.
- **Ads** are removed: the schedule that tells the player which ads to play
  is deleted before the page sees it, so there is nothing to skip.
- **Turning it off** needs a password that was generated for you and never
  shown. Sealing throws the password away and makes the installation put
  itself back when parts of it are removed.

The repository ships no policy. On first run you write two descriptions, what
to let through and what to keep out, and the model reads exactly those.

## Why it isn't a browser extension

An extension can be switched off in two clicks, and only covers one browser.
This runs below the browser instead:

1. A root-owned daemon points YouTube's hostnames at itself in `/etc/hosts`
   and restores those lines within seconds if they are edited.
2. It answers on `127.0.0.1:443` with certificates from a local authority
   created at install time, fetches the real page from YouTube, and rewrites
   it on the way through.
3. Recommendation data is deleted from the responses, not just hidden, and
   search and feed requests are refused at the proxy. Opening developer tools
   doesn't bring anything back.

Every browser that uses the system's hosts file and keychain gets the same
YouTube. If the daemon or its certificate is tampered with, YouTube stops
loading rather than coming back unfiltered.

### The certificate authority

Installing trusts a new root certificate, which deserves scrutiny. Two things
limit it:

- Both CA certificates carry a critical name constraint for `youtube.com`,
  `youtu.be` and `youtube-nocookie.com`. A certificate for any other domain
  signed by them fails verification (there is a test for this).
- The root's private key is never written to disk. It signs one intermediate
  and is discarded.

Only `www.youtube.com`, `youtube.com`, `m.youtube.com`, `youtu.be` and
`www.youtube-nocookie.com` are intercepted. Video streams and everything else
on the machine go direct.

## Install

Needs macOS, [Go](https://go.dev/dl/) 1.26.0 or later, and
[Ollama](https://ollama.com) with the classifier model pulled.

```sh
ollama pull gemma4:e4b
git clone https://github.com/Mathetic-PBC/youtube-hider
cd youtube-hider
go build -o ythider .
sudo ./ythider install
```

macOS asks once to approve trusting the certificate. Then quit and reopen
your browser and go to youtube.com: the first visit is the onboarding page.
Write your two descriptions (the suggestion pills are prompts, not defaults)
and save.

`--model NAME` picks a different Ollama model. If Ollama isn't running or the
model isn't pulled, everything is blocked until it is.

To move an installed copy to a newer build, with the policy and lock left as
they are:

```sh
git pull && go build -o ythider . && sudo ./ythider upgrade
```

## Changing what belongs

The policy page is at `https://www.youtube.com/__hider/onboard`, and linked
from every "Not approved" page.

- **Adding** to either description is always open. No password.
- **Rewriting or removing** needs the unlock password, and is impossible
  once sealed.
- **When something is in both** descriptions, it is kept out. Adding
  "tech reviews" to what's let through does not undo having it in what's
  kept out.

## Ads

A video's player data arrives with a schedule of ads: which to fetch and when
to play them. The proxy deletes that schedule (`adPlacements`, `playerAds`,
`adSlots`, `adBreakHeartbeatParams`) from every response that carries player
data, drops ad entries from result lists, and answers YouTube's own ad and
ad-tracking endpoints with nothing. This is the same removal browser ad
blockers perform inside the page, done one step earlier.

Two things it does not do:

- **It does not make YouTube forget an ad was due.** When the server had an
  ad scheduled and none is played, its stream server sometimes holds the
  video back for a few seconds. In testing on heavily monetized videos this
  showed up as a 4 to 9 second wait before some plays, and no wait before
  others. No ad played in any of them.
- **It cannot delete an ad that is spliced into the video stream itself.**
  For that case the injected script watches the player and, if it reports an
  ad, mutes it, jumps to its end and presses skip.

YouTube changes this regularly. The field names are in `rewrite.go` and the
in-page fallback in `web/inject.js`.

## Appeals

Each verdict comes with a confidence from 0 to 100. A block under 95 can be
appealed from the page that reports it: write at least 250 characters on why
you want it and what you are looking for, and it opens. A block the model is
sure of, because your description names the thing, has no appeal.

An accepted appeal covers that one search, video, channel or playlist from
then on. The text is kept in `appeals.json` next to the policy, so what you
let through and why can be read back later.

The confidence is the model's own report, steered by a rubric: 100 only when
a description names the subject or it is squarely one of the listed kinds,
60 to 85 for inference by resemblance. Left unsteered, the model answers 95
to 100 for everything, and the probability of its verdict token is no better.
The rubric is what makes the number separate "you named this" from "this
resembles something you named".

## Getting out

The password exists so that turning this off is a decision and not a reflex.
It is generated at install and not displayed.

```sh
sudo ythider request-unlock   # start the cool-off (24 hours by default)
sudo ythider cancel-unlock    # change your mind
sudo ythider reveal           # after the cool-off: prints the password
sudo ythider unlock           # asks for the password, removes everything
sudo ythider relock           # after a reveal: new password, not shown
```

`sudo ythider install --cooloff 72h` sets a different wait.
`--cooloff never` keeps no copy of the password at all, so there is nothing
to reveal.

### Sealing

`sudo ythider seal` is for when you want no way out. It cannot be undone.

- **No password.** The password is replaced with a new one and no copy is
  kept, so none of the commands above can ever open the lock.
- **The policy only grows.** You can still add to either description and
  appeal a block. Nothing can be rewritten or removed, on the policy page or
  by editing the file behind it.
- **It defends itself.** A second root daemon, the warden, starts. The proxy
  and the warden each put back the other's program and launchd entry and
  start the other again if it is stopped. Both keep the hosts entries, the
  lock and the machine setup as they were. The files carry the system
  immutable flag.
- **Upgrades still work.** `sudo ./ythider upgrade` replaces both daemons
  with the new build, so fixes can be deployed. That is the only change a
  sealed installation accepts.

Do not seal a copy you are only trying out. A sealed installation has no
uninstall command, and this README does not describe removing one by hand.

## What it does not stop

This raises the cost of an impulse. It is not a hard lock against the
machine's administrator, and no program can be: whoever holds root on a
machine can undo anything root installed on it. Sealing makes that a piece
of deliberate work with several parts that have to be done right at once. If
you need more than that, the person at the keyboard must not be an
administrator: use a standard account day to day and have someone else hold
the admin password.

Also out of scope:

- Other devices, and the YouTube apps on them.
- Your own history, playlists list and library pages, which load unjudged.
  The videos in them are judged when opened.
- The like, share and save buttons under a video, which stay.
- YouTube Music.
- Firefox, which keeps its own certificate store. YouTube won't load there
  unless `security.enterprise_roots.enabled` is turned on.

A video is judged from its title, channel and category, not its contents. A
lecture with a clickbait title can be blocked, and junk with a sober title
can pass.

## Measuring the classifier

A policy is a hypothesis about what the model will do with it. Test it:

```sh
ythider eval --policy policy.json queries.tsv
```

`policy.json` is `{"allowed": "...", "blocked": "..."}`. `queries.tsv` has one
labeled line per item: `allow<TAB>query` or `block<TAB>query` for a search,
and `allow<TAB>title<TAB>channel<TAB>category` for a video. The output lists
every disagreement with the model's confidence and reason, then agreement,
how many wrong blocks could have been appealed, and latency. Use `--model` to
compare models on the same file.

On an M5 Pro, `gemma4:e4b` answers in about 250 ms once loaded and about 3 s
for the first request after 30 idle minutes. It holds roughly 10 GB of memory
while loaded.

## Development

```sh
go test .
go build -o ythider . && ./ythider serve --dev --state /tmp/ythider-dev --listen 127.0.0.1:8443
```

`--dev` runs unprivileged with a throwaway authority and leaves `/etc/hosts`
alone. Point a scratch browser profile at it:

```sh
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --user-data-dir=/tmp/ythider-chrome --ignore-certificate-errors \
  --host-resolver-rules="MAP www.youtube.com 127.0.0.1:8443"
```

YouTube changes its page structure often. The proxy-side removal lives in
`rewrite.go` and `proxy.go`; the stylesheet that covers the rest is
`web/inject.css`.

## Status

Developed and checked against live YouTube in Chrome on macOS 27 using the
development mode above. The privileged paths (install, upgrade, seal and
the guard) cannot be exercised by the test suite, which covers their logic
against temporary directories; read `system.go` and `guard.go` before
running them.

## License

MIT
