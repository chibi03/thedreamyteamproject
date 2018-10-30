#include "tls.h"
#include <iostream>

std::ostream& operator<<(std::ostream& os, const alert_location& alert)
{
  os << "[loc=" << (alert.location == remote ? "remote" : "local") << ",alert=" << alert.alert
     << "]";
  return os;
}
