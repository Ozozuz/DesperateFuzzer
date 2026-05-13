# UnusualFuzzer

Burp Suite extension for the noble moment when the methodology reaches:

```text
E mo che posso fare?
Non ho altre idee.
```

So you fuzz the thing and hope the application explains itself by breaking.

## What It Does

- Adds a `UnusualFuzzer` tab to Burp.
- Adds `Send to Unusual Fuzzer` from Repeater.
- Lets you mark request entry points and highlight them.
- Sends raw, encoded, chained-encoded, or mutation-based payloads.
- Sorts results by status and length.
- Shows full request/response for every hit.

Encoding chains are intentionally stackable:

```text
plain -> url -> url
plain -> base64 -> url
```

Speed profiles are named scientifically:

```text
giuseppe = 1 thread
jacopo   = 3 threads
giulio   = 5 threads
```

## Build

Requires JDK 17+ and `lib/montoya-api-2026.4.jar`.

```bash
./scripts/build.sh
```

Load this in Burp:

```text
build/libs/UnusualFuzzer-0.1.0.jar
```
