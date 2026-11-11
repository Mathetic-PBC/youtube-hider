# youtube-hider

YouTube as a search bar. No home feed, no Shorts, no "up next", and every
search is checked by a model running on your Mac against what you said you
come to YouTube for.

- **Home** is a single search box. Nothing else loads.
- **Search results** show results. Shorts shelves, "people also watched"
  shelves and ads are removed.
- **Watch pages** play the video. The recommendation column, the end-of-video
  wall and autoplay are removed.
- **Each search** is classified by a local model in about 200 ms. A search
  that doesn't fit gets a "Not approved" page instead of results.
- **Turning it off** needs a password that was generated for you and never
  shown.

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
and save. From then on, changing them needs the password.

`--model NAME` picks a different Ollama model. If Ollama isn't running or the
model isn't pulled, searches are blocked until it is.

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

## What it does not stop

This raises the cost of an impulse. It is not a hard lock against the
machine's administrator, and can't be: anyone with `sudo` can unload the
daemon by hand. The password, the cool-off and the self-restoring hosts
entries are there so that getting around it takes deliberate work.

Also out of scope:

- Other devices, and the YouTube apps on them.
- A video opened by direct link. Only searches are classified.
- Channel pages, playlists and history, which still load.
- YouTube Music and embedded players on other sites. Embeds play, with the
  end-of-video suggestions hidden.
- A browser set up to resolve names somewhere else (a remote proxy or VPN
  that does its own DNS). iCloud Private Relay in Safari has not been tested.
- Firefox, which keeps its own certificate store. YouTube won't load there
  unless `security.enterprise_roots.enabled` is turned on.

## Measuring the classifier

A policy is a hypothesis about what the model will do with it. Test it:

```sh
ythider eval --policy policy.json queries.tsv
```

`policy.json` is `{"allowed": "...", "blocked": "..."}` and `queries.tsv` has
one labeled query per line, `allow<TAB>query` or `block<TAB>query`. The output
lists every disagreement with the model's reason, then agreement and latency.
Use `--model` to compare models on the same file.

On an M5 Pro, `gemma4:e4b` answers in about 200 ms once loaded and about 3 s
for the first search after 30 idle minutes. It holds roughly 10 GB of memory
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
development mode above. The privileged install path is new; read
`system.go` before running it.

## License

MIT
