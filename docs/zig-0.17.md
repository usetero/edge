# Zig 0.17 build

Use `./bin/zig` to select the compiler through Hermit.

The `policy_zig` dependency pins the published 0.8.0 release.
That release uses the published protobuf 7.0.0 dependency.

The `zimdjson` dependency pins the Zig 0.17 port in the remote fork.
All dependencies use immutable upstream commits and package hashes.
The build does not require sibling checkouts.

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
