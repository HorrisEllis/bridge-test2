# Bridge OS — GitHub Pages Relay Node

A silent relay node that runs on GitHub's CDN.

## What it is

A static HTML page that registers a Service Worker. The page shows a decoy 404 to anyone who visits directly. The Service Worker silently intercepts Bridge relay requests and forwards them through the phantom chain.

From the network:
- HTTPS to `*.github.io` — looks like normal CDN traffic
- GitHub CDN IP at every hop — unblockable without blocking GitHub entirely  
- No VPN fingerprint. No proxy headers. No unusual ports.
- Your IP is gone after the first hop.

## Deploy your own relay (5 minutes)

**Option A — Fork this repo**

1. Fork `HorrisEllis/Bridge-v2`
2. Go to Settings → Pages
3. Source: Deploy from a branch
4. Branch: `main` · Folder: `/relay`
5. Save

Your relay is live at:
```
https://<your-username>.github.io/Bridge-v2
```

**Option B — New repo**

1. Create a new public GitHub repo
2. Copy these three files into the root:
   - `index.html`
   - `relay-sw.js`  
   - `_config.yml`
3. Enable GitHub Pages: Settings → Pages → Source: main branch / root
4. Your relay: `https://<your-username>.github.io/<repo-name>`

## Add to Bridge phantom pool

```bash
# Add a single relay
node index.js --cli
> phantom relay add https://yourname.github.io/Bridge-v2

# Generate a magnet link with all your relays
> phantom relay magnet <your-node-id>
# Returns: nexus://4e336239?relay=https://yourname.github.io/Bridge-v2&relay=...
```

## Share via magnet link

The magnet link encodes your relay configuration. Anyone with Bridge OS pastes it once — they're routing through your relay chain automatically.

```
nexus://4e336239?relay=https://user1.github.io/relay-a&relay=https://user2.github.io/relay-b&relay=https://user3.github.io/relay-c
```

No app. No account. No configuration. One paste.

## Deploy many relays

Each GitHub account can host one relay per repo. Create multiple accounts, each hosting the relay template. Add all of them to your pool. When one gets noticed, rotate to the next. Generating a new one takes 5 minutes.

The attacker has to block GitHub to block your relay network. They won't.

## Security properties

- Each relay sees only the IP of the previous hop (GitHub CDN IP)
- Payload is AES-256-GCM encrypted end-to-end — relay cannot read content
- Nonce prevents replay attacks
- SSRF protection — relay cannot be used to probe private networks
- No logging — Service Worker state is ephemeral, clears on restart
- Timing jitter per hop — defeats naive traffic correlation

## What the relay does NOT do

- Cannot read your traffic (encrypted before it arrives)
- Cannot identify you (your IP is gone after hop 1)
- Cannot be used as an open proxy to arbitrary services (HTTPS to public hosts only)
- Does not store anything (ephemeral Service Worker)

---

*Bridge OS · James Brooks (Erosmancer) · rheon.world · github.com/HorrisEllis/Bridge-v2*
