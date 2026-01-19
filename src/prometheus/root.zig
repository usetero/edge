//! Prometheus Module
//!
//! Provides Prometheus exposition format parsing and metric filtering.
//!

pub const line_parser = @import("line_parser.zig");
pub const streaming_filter = @import("streaming_filter.zig");
pub const field_accessor = @import("field_accessor.zig");

// Re-export commonly used types
pub const ParsedLine = line_parser.ParsedLine;
pub const LabelIterator = line_parser.LabelIterator;
pub const Label = line_parser.Label;
pub const MetricType = line_parser.MetricType;
pub const parseLine = line_parser.parseLine;

pub const PolicyStreamingFilter = streaming_filter.PolicyStreamingFilter;
pub const FilterStats = streaming_filter.FilterStats;
pub const ProcessResult = streaming_filter.ProcessResult;

pub const PrometheusFieldContext = field_accessor.PrometheusFieldContext;
pub const prometheusFieldAccessor = field_accessor.prometheusFieldAccessor;
pub const buildLabelsCache = field_accessor.buildLabelsCache;

test {
    _ = line_parser;
    _ = streaming_filter;
    _ = field_accessor;
}
