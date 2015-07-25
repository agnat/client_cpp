#include "output_formatter.hh"

#include <iostream>

namespace prometheus {
namespace impl {

OutputFormatter::OutputFormatter(std::ostream& os) : os_(os) {}

void OutputFormatter::addMetric(std::string const& name,
                                std::string const& type) {
  os_ << "# HELP " << name << std::endl;  // TODO(korfuri): Add description.
  os_ << "# TYPE " << name << ' ' << type << std::endl;
}

void OutputFormatter::addMetricValue(std::string const& name, double value) {
  os_ << name << " = " << value << std::endl;
}

} /* namespace impl */
} /* namespace prometheus */