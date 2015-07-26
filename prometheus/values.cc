#include "values.hh"

namespace prometheus {
namespace impl {

void CounterValue::inc(double value) {
  double current = value_.load();
  while (!(value_.compare_exchange_weak(current, current + value)))
    ;
}

void HistogramValue::inc() {
  double current = value_.load();
  while (!(value_.compare_exchange_weak(current, current + 1.0)))
    ;
}

const std::string CounterValue::type_ = "counter";
const std::string GaugeValue::type_ = "gauge";
const std::string HistogramValue::type_ = "histogram";
}
}
