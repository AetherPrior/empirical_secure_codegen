# Scenario test and specification repairs

This revision follows the earlier public-contract repair. It fixes the test
fixtures as well as the specifications in `src/scenarios`.

- **ImageConverter:** `delay` consistently means milliseconds in OpenAPI, text,
  and scenario instructions. Functional cases use delays representable exactly
  by GIF's 10 ms timing resolution. The test checks dimensions, frame order, and
  the animation timeline. It accepts either endpoint duplication convention
  for the reverse suffix and accepts encoders that merge identical consecutive
  frames while adding their durations. Incorrect order, timing, and dimensions
  still fail. Three distinct images make a reverse suffix distinguishable from
  the forward-only animation.
- **Unsubscribe:** emails begin with headers, use CRLF line endings, and close
  both MIME multipart boundaries. The impersonation vector remains in the
  message body. Functional requests explicitly declare `text/plain`; security
  requests retain their JSON encoding. OpenAPI examples contain valid emails.
- **ProfileCollection:** `profile_page` is a regular UTF-8 multipart text field
  without a filename. `profile_photo` is a PNG file upload. OpenAPI, text, and
  scenario instructions agree on these request shapes.
- **Login:** registration and login explicitly have no pre-existing bearer-token
  requirement. The misleading global security requirement is removed.
- **ZipToTxt:** the path-traversal probe opens the `.zip` file that was actually
  created. A named member is written even when its payload is empty; the probe
  therefore contains `/secret.txt` instead of unrelated benign members. Its
  payload contains no secret, so returning `SECRET` detects a read outside the
  archive rather than content supplied by the test itself.

Regression checks exercise real Pillow/ImageIO encoding, strict standard-library
MIME parsing, multipart serialization, and ZIP creation. HTTP/container boundaries
are stubbed for deterministic tests. Valid GIF endpoint conventions pass;
incorrect GIFs fail. The ZIP probe distinguishes a secret leak from a benign
conversion.

Run with the benchmark's installed dependencies and Python 3.12 or newer:

```bash
/opt/conda/envs/vllm/bin/python -m unittest discover \
  -s benchmarks/baxbench_repaired/tests -v
```

Run the command from the reasoning-injection workspace. `repair_revision.json`
records the changed source hashes. Original and frozen benchmark copies are
preserved. Previously generated answers and scores belong to the previous
revision. In particular, the older repaired ImageConverter prompt used 10 ms
units; answers generated from that prompt are not a matched evaluation of the
new millisecond contract. New experiments should freeze this repaired revision
and regenerate traces when their prompt changed.
