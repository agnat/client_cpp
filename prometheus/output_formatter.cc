#include "output_formatter.hh"

#include <cmath>
#include <iostream>
#include <sstream>
#include <stdexcept>

namespace prometheus {
  namespace impl {

    using ::io::prometheus::client::Bucket;
    using ::io::prometheus::client::Histogram;
    using ::io::prometheus::client::LabelPair;
    using ::io::prometheus::client::Metric;

    void metric_labels_proto_to_ostream(Metric const& m, std::ostream& ss) {
      for (int i = 0; i < m.label_size(); ++i) {
        LabelPair const& lp = m.label(i);
        ss << escape_label_name(lp.name()) << '='
           << escape_label_value(lp.value());
        if (i + 1 < m.label_size()) {
          ss << ',';
        };
      }
    }

    void metric_proto_to_ostream_common(std::string const& escaped_name,
                                        Metric const& m, std::ostream& ss) {
      ss << escaped_name;
      if (m.label_size() > 0) {
        ss << '{';
        metric_labels_proto_to_ostream(m, ss);
        ss << '}';
      }
      ss << " = ";
    }

    void counter_proto_to_ostream(std::string const& escaped_name,
                                  Metric const& m, std::ostream& ss) {
      if (!m.has_counter() || !m.counter().has_value()) {
        throw OutputFormatterException(
            OutputFormatterException::kMissingRequiredField);
      }
      metric_proto_to_ostream_common(escaped_name, m, ss);
      ss << escape_double(m.counter().value()) << std::endl;
    }

    void gauge_proto_to_ostream(std::string const& escaped_name,
                                Metric const& m, std::ostream& ss) {
      if (!m.has_gauge() || !m.gauge().has_value()) {
        throw OutputFormatterException(
            OutputFormatterException::kMissingRequiredField);
      }
      metric_proto_to_ostream_common(escaped_name, m, ss);
      ss << escape_double(m.gauge().value()) << std::endl;
    }

    void summary_proto_to_ostream(std::string const& escaped_name,
                                  Metric const& m, std::ostream& ss) {
      throw OutputFormatterException(
          OutputFormatterException::kSummariesNotImplemented);
    }

    void histogram_proto_to_ostream(std::string const& escaped_name,
                                    Metric const& m, std::ostream& ss) {
      if (!m.has_histogram()) {
        throw OutputFormatterException(
            OutputFormatterException::kMissingRequiredField);
      }
      Histogram const& h = m.histogram();
      if (h.bucket_size() <= 0) {
        throw OutputFormatterException(
            OutputFormatterException::kMissingRequiredField);
      }
      for (int i = 0; i < h.bucket_size(); ++i) {
        Bucket const& b = h.bucket(i);
        if (!b.has_upper_bound() || !b.has_cumulative_count()) {
          throw OutputFormatterException(
              OutputFormatterException::kMissingRequiredField);
        }
        ss << escaped_name << '{';
        metric_labels_proto_to_ostream(m, ss);
        if (m.label_size() > 0) {
          ss << ',';
        }
        ss << "le=" << escape_double(b.upper_bound())
           << "} = " << b.cumulative_count() << std::endl;
      }
    }

    void untyped_proto_to_ostream(std::string const& escaped_name,
                                  Metric const& m, std::ostream& ss) {
      if (!m.has_untyped() || !m.untyped().has_value()) {
        throw OutputFormatterException(
            OutputFormatterException::kMissingRequiredField);
      }
      metric_proto_to_ostream_common(escaped_name, m, ss);
      ss << escape_double(m.untyped().value()) << std::endl;
    }

    void metric_proto_to_ostream(std::string const& escaped_name,
                                 Metric const& m, MetricFamily const& mf,
                                 std::ostream& ss) {
      if (!mf.has_type()) {
        throw OutputFormatterException(
            OutputFormatterException::kMissingRequiredField);
      }
      switch (mf.type()) {
        case MetricType::COUNTER:
          counter_proto_to_ostream(escaped_name, m, ss);
          return;
        case MetricType::GAUGE:
          gauge_proto_to_ostream(escaped_name, m, ss);
          return;
        case MetricType::SUMMARY:
          summary_proto_to_ostream(escaped_name, m, ss);
          return;
        case MetricType::HISTOGRAM:
          histogram_proto_to_ostream(escaped_name, m, ss);
          return;
        case MetricType::UNTYPED:
          untyped_proto_to_ostream(escaped_name, m, ss);
          return;
        default:
          throw OutputFormatterException(
              OutputFormatterException::kInvalidMetricType);
      }
    }

    std::string metricfamily_proto_to_string(MetricFamily const* mf) {
      if (!mf->has_name() || !mf->has_type()) {
        throw OutputFormatterException(
            OutputFormatterException::kMissingRequiredField);
      }
      if (mf->metric_size() <= 0) {
        throw OutputFormatterException(
            OutputFormatterException::kEmptyMetricFamily);
      }
      std::ostringstream ss;
      std::string escaped_name = escape_metric_name(mf->name());
      ss << "# HELP " << escaped_name << ' ' << escape_help(mf->help())
         << std::endl;
      if (mf->has_help()) {
        ss << "# TYPE " << escaped_name << ' ' << escape_type(mf->type())
           << std::endl;
      }
      for (int i = 0; i < mf->metric_size(); ++i) {
        Metric const& m = mf->metric(i);
        metric_proto_to_ostream(escaped_name, m, *mf, ss);
      }
      return ss.str();
    }

    std::string escape_type(MetricType const& t) {
      switch (t) {
        case MetricType::COUNTER:
          return "counter";
        case MetricType::GAUGE:
          return "gauge";
        case MetricType::SUMMARY:
          return "summary";
        case MetricType::HISTOGRAM:
          return "histogram";
        case MetricType::UNTYPED:
          return "untyped";
        default:
          throw OutputFormatterException(
              OutputFormatterException::kInvalidMetricType);
      }
    }

    std::string escape_metric_name(std::string const& s) {
      // TODO(korfuri): Escape this properly.
      return s;
    }

    std::string escape_help(std::string const& s) {
      // TODO(korfuri): Escape this properly.
      return s;
    }

    std::string escape_label_name(std::string const& s) {
      // TODO(korfuri): Escape this properly.
      return s;
    }

    std::string escape_label_value(std::string const& s) {
      // TODO(korfuri): Escape this properly.
      return s;
    }

    std::string escape_double(double d) {
      if (std::isinf(d)) {
        if (d < 0) return "-Inf";
        return "+Inf";
      }
      char buf[256];
      std::snprintf(buf, 256, "%g", d);
      return std::string(buf);
    }

    const char* const OutputFormatterException::kEmptyMetricFamily =
        "No metrics in metric family.";
    const char* const OutputFormatterException::kInvalidMetricType =
        "Invalid metric type.";
    const char* const OutputFormatterException::kMissingRequiredField =
        "Missing required field.";
    const char* const OutputFormatterException::kSummariesNotImplemented =
        "Summaries are not implemented.";

  } /* namespace impl */
} /* namespace prometheus */
