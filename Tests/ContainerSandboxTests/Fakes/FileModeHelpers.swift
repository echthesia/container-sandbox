import Foundation

/// Read the POSIX mode bits of a file or directory. Returns 0 on stat failure
/// so tests can `#expect(modeBits(...) == 0o600)` without unwrapping.
func modeBits(of url: URL) -> mode_t {
    var st = stat()
    guard stat(url.path, &st) == 0 else { return 0 }
    return st.st_mode & 0o777
}
