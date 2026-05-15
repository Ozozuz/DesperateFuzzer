# DesperateFuzzer

Burp Suite extension for the noble moment when the methodology reaches:

```text
E mo che posso fare?
Non ho altre idee.
```

So you fuzz the thing and hope the application explains itself by breaking.

<img src="assets/desperate-fuzzer-meme.jpg" alt="DesperateFuzzer trade offer meme" width="320">

## What It Does

- Turns "I have no more ideas" into 256 requests and a mild sense of purpose.
- Sends raw, encoded, chained-encoded, or mutation-based payloads into whatever parameter looks guilty.
- Lets you stack encodings until the backend starts questioning its career choices.
- Highlights weird results, because apparently reading 256 almost-identical rows is a personality flaw.
- Keeps the full request/response around, so your future self can still pretend this was a controlled experiment.
- Mutation mode starts from something valid and makes it worse with confidence.

Encoding chains are intentionally stackable:

```text
empty pipeline = plain/raw
url -> url
base64 -> url
```

Speed profiles are named scientifically:

```text
giuseppe = 2 threads
jacopo   = 6 threads
giulio   = 10 threads
```

## Build

Requires JDK 17+ and `lib/montoya-api-2026.4.jar`.

```bash
./scripts/build.sh
```

Load this in Burp:

```text
build/libs/UnusualFuzzer-0.2.0.jar
```
