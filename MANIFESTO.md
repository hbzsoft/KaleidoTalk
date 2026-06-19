# KaleidoTalk Manifesto

## Privacy Is a Fundamental Human Right

When I realized my private data was being used to target ads at me, I felt angry and powerless.

Large companies collect our privacy without truly asking for consent. That is not the world I want to live in. Encryption should not be a privilege for a few; it should be the default for everyone.

So I decided to build, from scratch, a chat app that truly respects users: KaleidoTalk.

## What We Believe

**1. End-to-end encryption is non-negotiable**  
From sender to receiver, only the two of you should be able to read messages. No server, ISP, government, or even me as the author should be able to decrypt your conversations.

**2. Code must be open source**  
Closed source software cannot be fully trusted. All KaleidoTalk code is published under GPL v3, so anyone can audit, modify, and run it.

**3. Users control trust**  
We do not rely on centralized certificate authorities. Identity is verified by comparing fingerprint words (from the BIP39 wordlist) in person or over a trusted call. Trust is your choice.

**4. Metadata must also be protected**  
Encrypting message content alone is not enough. Since v2.3, KaleidoTalk uses fixed-length packets and randomized heartbeat traffic so outsiders cannot easily infer behavior from packet sizes and timing patterns.

**5. Transparent, simple, and not greedy**  
No ads, no data mining, no hidden trackers. We do not collect users' personal information.

## What We Are Not

- Not a VPN and not a censorship-circumvention tool. KaleidoTalk does not help bypass network controls.
- Not a company and not a public chat service provider. I provide code; you can run your own server for yourself and friends.
- Not a perfect anonymity tool. If you need identity anonymity, combine it with networks such as Tor.

## Responsibility Boundary

- **The code is free, but usage must be lawful.** When you deploy or use KaleidoTalk, you are responsible for compliance with local law.
- **I (the author) am not legally responsible for third-party deployments.** If you operate a server, compliance requirements such as identity verification, registration, and content governance are your responsibility.

## Join Us

You do not need to run a huge network to make a difference. Download the code, run a small server for yourself and your friends, and explain why privacy is worth defending. Every such step makes the world a little better.

**Privacy is a human right.  
We write code to protect it.**

— Bangze Han, 2026
