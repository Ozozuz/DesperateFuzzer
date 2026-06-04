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

## How Signals Are Chosen

The `Signal` column exists because scrolling through hundreds of identical-looking responses is not a personality test anyone should have to pass.

Every result starts as normal. Then DesperateFuzzer gets suspicious in three ways:

- **Status rarity**: results are grouped by entry point, then by HTTP status. A lonely `500` in a sea of `200`s is an `outsider`; a small but not microscopic status group is `interesting`. Revolutionary concept: different status codes may mean different things.
- **Length drift**: lengths are compared only inside the same entry point and same status group. A weird `200` is compared with other `200`s, not with redirects, because chaos is not a baseline. Big body-size deviations become `outsider`; moderate ones become `interesting`.
- **Error signatures**: the response body is grepped for boringly useful leaks like `ORA-00933`, `SQLSTATE`, Java/Python/.NET/PHP stack traces, Spring internals, Go panics, and debug-page classics. A match promotes the row to at least `interesting`, because if the app prints a stack trace, it is probably trying to confess.

The `Match` column shows which explicit error/debug signature was found. This never downgrades a stronger signal: if a row is already an `outsider`, finding a stack trace does not politely demote it to "mildly spicy".

## Build

Requires JDK 17+ and `lib/montoya-api-2026.4.jar`.

```bash
./scripts/build.sh
```

Load this in Burp:

```text
build/libs/DesperateFuzzer-0.2.1.jar
```
