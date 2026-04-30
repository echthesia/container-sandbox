/// Version string surfaced via `container sandbox --version`.
///
/// `make package VERSION=v0.1.0` rewrites this constant before building
/// the release binary; the checked-in value is the in-development marker
/// so local builds say "dev" instead of impersonating a real tag.
let containerSandboxVersion = "0.0.0-dev"
