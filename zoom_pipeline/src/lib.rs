//! zoom_pipeline: the Retina-independent core of zoom_capture.
//!
//! Layout (packet path first):
//! * [`net`]      allocation-free Ethernet/VLAN/IP/UDP parser
//! * [`ipset`]    Zoom server address gate (binary search)
//! * [`dedup`]    live de-duplication of second copies (one table shared by all cores)
//! * [`headers`]  Zoom SFU / media header parsing: types, per-type RTP offsets, the three video layouts
//!                (media byte 20), the type-13 sub-type gate (media byte 7)
//! * [`agg`]      per-core aggregation shard, bounded, chunk-swept
//! * [`pipeline`] glue: the per-packet function, health, sweeper, shutdown
//! * [`export`]   assembler, Influx line protocol, sinks, exporter thread
//! * [`csvdump`]  optional per-packet debug CSV
pub mod agg;
pub mod capture_files;
pub mod csvdump;
pub mod dedup;
pub mod export;
pub mod headers;
pub mod health;
pub mod ipset;
pub mod metrics;
pub mod model;
pub mod net;
pub mod pipeline;
pub mod report;
