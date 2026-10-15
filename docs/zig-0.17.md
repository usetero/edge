# Local Zig 0.17 build

Use `./bin/zig` to select the compiler through Hermit.

The `policy_zig` dependency points to the sibling checkout at `../policy-zig`.
That checkout needs the Zig 0.17 port and its local Zig 0.17 protobuf dependency.

Do not publish this manifest with the local policy path.
Replace the path with an immutable URL and hash before a release.

The `zimdjson` dependency points to the sibling fork at `../zimdjson`.
That checkout needs the Zig 0.17 port.
The other dependencies use immutable upstream commits.

The codec build uses one `TranslateC` step for the compression headers.
Zig 0.17 still supports this step. This avoids a new translation dependency.
The step discovers the compression headers through the system libraries.

Run the local checks:

```sh
./bin/zig version
./bin/zig build --summary all
./bin/zig build test --summary all
./bin/zig build -Dfrontend=httpz --summary all
./bin/zig build datadog otlp prometheus tail edge lambda --summary all
PATH="$PWD/bin:$PATH" ./bin/task lint
```
