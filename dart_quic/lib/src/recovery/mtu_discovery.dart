/// RFC 8899 (DPLPMTUD, Datagram Packetization Layer Path MTU
/// Discovery) -- a deliberately simplified binary-search prober,
/// scoped to this library's own actual need (see this class's own
/// doc comment) rather than a full implementation of every optional
/// mechanism RFC 8899 describes (e.g. this never PROBES DOWN again
/// once a size is confirmed working -- no PLPMTU aging/black-hole
/// re-detection -- since DESIGN.md's scope is a client that reconnects
/// on any real connectivity change anyway, not a long-lived connection
/// expected to survive an in-flight path MTU reduction).
library;

/// A size this prober will never go below -- RFC 9000 §14.1's own
/// unconditionally-guaranteed floor every compliant QUIC path must
/// support without any discovery at all. [MtuDiscoverer] never probes
/// or reports anything smaller than this, matching how RFC 8899 itself
/// defines "base PLPMTU" as a size assumed to always work.
const int kBaseMtu = 1200;

/// The size [MtuDiscoverer] stops searching above -- matches this
/// library's own datagram/packet buffer sizing headroom (see
/// connection.dart's own send path) and comfortably covers real-world
/// Ethernet/PPPoE MTUs (1500) plus a little slack; searching further
/// up has no benefit for commander's own low-bandwidth-link scope
/// (DESIGN.md) and would just cost more probe round trips for probe
/// sizes no real deployed path is likely to need.
const int kMaxProbeMtu = 1452;

/// RFC 8899 §5.1.2: how close the search interval must narrow before
/// discovery is considered done -- once `max - min <= kMtuSearchGranularity`,
/// further probing wouldn't meaningfully change the result. Matches
/// quic-go's own `maxMTUDiff` (see that project's `mtu_discoverer.go`,
/// used here purely as a today's-known-good-value reference point, not
/// a wire-compatibility requirement -- MTU discovery is a purely local
/// decision with no on-wire negotiation for the algorithm itself).
const int kMtuSearchGranularity = 20;

/// How many probe losses at a given size this prober tolerates before
/// concluding that size itself (not ordinary packet loss) is the
/// reason -- RFC 8899 §5.1.3's own "PROBE_COUNT" concept, kept small
/// since a probe that's genuinely too large for the path is dropped
/// deterministically (not lost intermittently) on the overwhelming
/// majority of real paths (a hard MTU ceiling, not a lossy-but-
/// sometimes-works one) -- unlike ordinary congestion-driven packet
/// loss, which this class relies on the SAME probe size being retried
/// at a SMALLER candidate next time to distinguish from.
const int kMaxProbeAttempts = 3;

/// Binary-searches for the largest UDP payload size this connection's
/// own path actually delivers, without assuming any fixed "safe MTU"
/// number -- see connection.dart's own `kMaxStreamFrameChunkSize`
/// doc comment for the real-world regression this exists to prevent
/// (a VPN/tunneled path with an actual MTU well under the 1400-byte
/// value that constant used to assume, silently dropping every
/// maximally-sized packet with no error, since QUIC/UDP has no built-in
/// "packet too big" signal the way ICMP fragmentation-needed messages
/// give TCP).
///
/// Usage (see connection.dart's own integration): construct once per
/// connection, call [start] once the connection is up, then on each
/// send-opportunity check [shouldProbe] and if true call [nextProbeSize]
/// to learn how large a PING-only packet to send; feed the result back
/// via [onProbeAcked]/[onProbeLost] once its own fate (ACKed vs
/// declared lost by the ordinary loss detector) is known. [currentMtu]
/// is the safe, already-confirmed size to actually use for STREAM-frame
/// chunking at any point -- starts at [kBaseMtu] (RFC 9000's own
/// guaranteed floor) and only ever increases as probes succeed, so a
/// caller reading it mid-discovery always gets a safe (if possibly not
/// yet maximal) value, never an unconfirmed one.
class MtuDiscoverer {
  int _min;
  int _max;
  int? _inFlightProbeSize;
  int _lossesAtCurrentCandidate = 0;
  bool _started = false;

  MtuDiscoverer({int min = kBaseMtu, int max = kMaxProbeMtu})
      : _min = min,
        _max = max;

  /// The largest size confirmed (via a successfully-ACKed probe, or
  /// the still-unconfirmed starting floor) to actually work on this
  /// path -- always safe to use immediately for real STREAM-frame
  /// chunking, even before [isDone].
  int get currentMtu => _min;

  /// Whether the search has narrowed enough that further probing
  /// wouldn't meaningfully change [currentMtu] (RFC 8899 §5.1.2) --
  /// callers may keep calling [shouldProbe] afterward too (it simply
  /// always returns false once done), this getter just names the
  /// state explicitly for tests/diagnostics.
  bool get isDone => _max - _min <= kMtuSearchGranularity;

  /// Marks discovery as active -- [shouldProbe] returns false before
  /// this is called, matching how a connection shouldn't start probing
  /// before the path/keys it needs even exist yet.
  void start() {
    _started = true;
  }

  /// Whether the caller should send a probe packet right now (no probe
  /// currently in flight, and the search isn't done yet).
  bool get shouldProbe =>
      _started && _inFlightProbeSize == null && !isDone;

  /// The size (in bytes) of the next probe packet to send -- always
  /// the midpoint of the current search interval, matching RFC 8899's
  /// own binary-search strategy. Marks that size as in flight; callers
  /// must eventually report its fate via [onProbeAcked]/[onProbeLost]
  /// (or [onGenerationReset], if the connection's own path changed
  /// meanwhile) before another probe will be issued.
  int nextProbeSize() {
    final size = (_min + _max) ~/ 2;
    _inFlightProbeSize = size;
    return size;
  }

  /// Call when a probe packet's own fate is confirmed ACKed (via the
  /// ordinary ACK-processing path, matched back to this probe's own
  /// packet number by the caller) -- the path is now confirmed to
  /// support at least this size; narrows the search interval upward
  /// and clears this candidate's own loss counter (a fresh size gets a
  /// fresh attempt budget).
  void onProbeAcked(int probeSize) {
    if (_inFlightProbeSize != probeSize) return; // stale/mismatched report
    _inFlightProbeSize = null;
    _lossesAtCurrentCandidate = 0;
    if (probeSize > _min) _min = probeSize;
  }

  /// Call when a probe packet is declared lost by the ordinary loss
  /// detector. Unlike an ordinary retransmittable frame, a lost MTU
  /// probe is NEVER retransmitted at the same size (RFC 8899 §5.1.3):
  /// after [kMaxProbeAttempts] losses at this exact candidate size
  /// without ever confirming it works, this concludes the size itself
  /// -- not incidental network loss -- is the reason, and narrows the
  /// search interval's own upper bound down to just below it so the
  /// next [nextProbeSize] call tries something smaller instead of
  /// repeating a size that's already failed enough times to be
  /// considered conclusively unsupported.
  void onProbeLost(int probeSize) {
    if (_inFlightProbeSize != probeSize) return; // stale/mismatched report
    _inFlightProbeSize = null;
    _lossesAtCurrentCandidate++;
    if (_lossesAtCurrentCandidate >= kMaxProbeAttempts) {
      _lossesAtCurrentCandidate = 0;
      if (probeSize < _max) _max = probeSize;
    }
    // Fewer than kMaxProbeAttempts losses so far: leave the interval
    // unchanged and let the next shouldProbe/nextProbeSize retry the
    // SAME midpoint -- a single loss is at least as likely to be
    // ordinary network loss as an actual MTU ceiling, so one loss
    // alone must not move the search.
  }

  /// Resets the search entirely (e.g. after a detected path change --
  /// out of scope for this library today per DESIGN.md, connection
  /// migration isn't implemented, but exposed for forward-compatibility
  /// and for tests that want a clean-slate finder without constructing
  /// a new one).
  void reset({int min = kBaseMtu, int max = kMaxProbeMtu}) {
    _min = min;
    _max = max;
    _inFlightProbeSize = null;
    _lossesAtCurrentCandidate = 0;
  }
}
