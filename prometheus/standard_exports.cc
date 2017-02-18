#include "collector.hh"
#include "registry.hh"
#include "standard_exports.hh"
#include "prometheus/proto/metrics.pb.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <dirent.h>
#include <errno.h>
#include <fstream>
#include <iostream>
#include <sstream>

#ifdef __APPLE__
# include <libproc.h>
# include <sys/resource.h>
# include <sys/sysctl.h>
# include <mach/task.h>
# include <mach/task_info.h>
# include <mach/mach_init.h>
#endif // __APPLE__

namespace prometheus {
  namespace impl {
    struct ProcSelfStatReader {

      ProcSelfStatReader() {
        std::ifstream in("/proc/self/stat");
        // Extracts all fields from /proc/self/stat. This assumes a
        // Linux 2.6 distro (importantly, times are expressed in ticks
        // and not in jffies). Not all fields are actually used for
        // exports.
        in
          >> pid >> filename >> state >> ppid >> pgrp
          >> session >> ttynr >> tpgid >> flags >> minflt
          >> cminflt >> majflt >> cmajflt >> utime >> stime
          >> cutime >> cstime >> priority >> nice >> numthreads
          >> itrealvalue >> starttime >> vsize >> rss;
      }

      char state;
      int pid, ppid, pgrp, session, ttynr, tpgid;
      unsigned int flags;
      unsigned long int minflt, cminflt, majflt, cmajflt, utime, stime;
      long int cutime, cstime, priority, nice, numthreads, itrealvalue;
      unsigned long long int starttime;
      unsigned long int vsize;
      long int rss;
      std::string filename;
    };

    struct ProcStatReader {
      ProcStatReader() {
        std::ifstream in("/proc/stat");
        std::string line;
        while (in.good()) {
          std::getline(in, line);
          if (line.compare(0, 6, "btime ") == 0) {
            btime = std::stoi(line.substr(6));
          }
        }
      }

      long int btime;
    };

    struct ProcSelfFdReader {
      class OpenDirException {};

      ProcSelfFdReader() : num_open_files(0) {
        DIR* dir = opendir("/proc/self/fd");
        if (dir == nullptr) {
          throw OpenDirException();
        }

        errno = 0;
        while (readdir(dir)) {
          ++num_open_files;
        }
        closedir(dir);
        if (errno) {
          throw OpenDirException();
        }
      }

      rlim_t num_open_files;
    };

    struct ProcSelfLimitsReader {
      ProcSelfLimitsReader() {
        std::ifstream in("/proc/self/limits");
        std::string line;
        while (in.good()) {
          std::getline(in, line);
          if (line.compare(0, 14, "Max open files") == 0) {
            max_open_files = std::stoi(line.substr(14));
          }
        }
      }

      rlim_t max_open_files;
    };

    class ProcessCollector : public ICollector {
    public:
      ProcessCollector() {
        global_registry.register_collector(this);
      }
      ~ProcessCollector() {
        global_registry.unregister_collector(this);
      }
      
    protected:
      static
      void
      set_virtual_memory(collection_type & l, double value) {
        set_gauge(l, "process_virtual_memory_bytes", "Virtual memory size in bytes (vsize)", value);
      }

      static
      void
      set_resident_memory(collection_type & l, double value) {
        set_gauge(l, "process_resident_memory_bytes", "Resident memory size in bytes (rss)", value);
      }

      static
      void
      set_start_time(collection_type & l, double value) {
        set_gauge(l, "process_start_time_seconds", "Start time of the process since unix epoch in seconds.", value);
      }

      static
      void
      set_cpu_time(collection_type & l, double value) {
        set_gauge(l, "process_cpu_seconds_total", "Total user and system CPU time spent in seconds.", value);
      }

      static
      void
      set_open_fds(collection_type & l, double value) {
        set_gauge(l, "process_open_fds", "Number of open file descriptors.", value);
      }

      static
      void
      set_max_fds(collection_type & l, double value) {
        set_gauge(l, "process_max_fds", "Maximum number of open file descriptors.", value);
      }
      // Convenience function to add a gauge to the list of
      // MetricFamilies and set its name/help/type and one value.
      static
      void
      set_gauge(collection_type& l,
                std::string const& name,
                std::string const& help,
                double value) {
        MetricFamily* mf = new MetricFamily();
        mf->set_name(name);
        mf->set_help(help);
        mf->set_type(::prometheus::client::MetricType::GAUGE);
        mf->add_metric()->mutable_gauge()->set_value(value);
        l.push_back(MetricFamilyPtr(mf));
      }
    };

    class LinuxProcessCollector : public ProcessCollector {
    public:
      LinuxProcessCollector() :
        pagesize_(sysconf(_SC_PAGESIZE)),
        ticks_per_ms_(sysconf(_SC_CLK_TCK)) {
      }

      collection_type collect() const {
        collection_type l;
        ProcSelfStatReader pss;
        ProcStatReader ps;
        ProcSelfFdReader psfd;
        ProcSelfLimitsReader psl;

        set_virtual_memory(l, pss.vsize);
        set_resident_memory(l, pss.rss * pagesize_);
        set_start_time(l, pss.starttime / ticks_per_ms_ + ps.btime);
        set_cpu_time(l, (double)(pss.utime + pss.stime) / ticks_per_ms_);
        set_open_fds(l, psfd.num_open_files);
        set_max_fds(l, psl.max_open_files);
        return l;
      }
    private:
      const double pagesize_;
      const double ticks_per_ms_;
    };

#ifdef __APPLE__
    double
    timeval_to_double(timeval const& tv) {
      return tv.tv_sec + tv.tv_usec * 1e-6;
    }

    void
    kinfo_for_pid(kinfo_proc * kinfo, pid_t pid) {
      const size_t miblen = 4;
      int mib[miblen] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
      size_t len = sizeof(kinfo_proc);
      int result = sysctl(mib, miblen, kinfo, &len, NULL, 0);
      if (result != 0) {
        std::ostringstream error;
        error << "sysctl() failed: " << strerror(errno);
        throw std::runtime_error(error.str());
      }
    }

    class MachTaskInfo {
    public:
      MachTaskInfo() {
        mach_msg_type_number_t count = TASK_BASIC_INFO_64_COUNT;
        kern_return_t result = task_info(mach_task_self(), TASK_BASIC_INFO_64,
            (task_info_t)&task_info_, &count);
        if (result != KERN_SUCCESS) {
          throw std::runtime_error("task_info() failed");
        }
      }

      size_t virtual_size() const { return task_info_.virtual_size; }
      size_t resident_size() const { return task_info_.resident_size; }

    private: // data members
      task_basic_info task_info_;
    };

    class MacOSProcessCollector : public ProcessCollector {
    public: // member functions
      MacOSProcessCollector() :
        pid_(getpid()),
        starttime_(get_start_time())
      {}

      collection_type
      collect() const {
        collection_type l;
        MachTaskInfo task_info;

        set_virtual_memory(l, task_info.virtual_size());
        set_resident_memory(l, task_info.resident_size());
        set_start_time(l, starttime_);
        set_cpu_time(l, get_cpu_time());
        set_open_fds(l, get_open_fds());
        set_max_fds(l, get_max_fds());
        return l;
      }

    private: // member functions

      double
      get_start_time() const {
        kinfo_proc kinfo;
        kinfo_for_pid(&kinfo, pid_);
        return timeval_to_double(kinfo.kp_proc.p_starttime);
      }

      double
      get_cpu_time() const {
        rusage resources;
        int result = getrusage(RUSAGE_SELF, &resources);
        if (result != 0) {
          std::ostringstream error;
          error << "getrusage() failed: " << strerror(errno);
          throw std::runtime_error(error.str());
        }
        timeval total;
        timeradd(&resources.ru_utime, &resources.ru_stime, &total);
        return timeval_to_double(total);
      }

      size_t
      get_open_fds() const {
        int result = proc_pidinfo(pid_, PROC_PIDLISTFDS, 0, NULL, 0);
        if (result < 0) {
          std::ostringstream error;
          error << "proc_pidinfo() failed to get buffer size: " << result;
          throw std::runtime_error(error.str());
        }
        size_t count = result / PROC_PIDLISTFD_SIZE;
        std::vector<proc_fdinfo> buffer(count);
        result = proc_pidinfo(pid_, PROC_PIDLISTFDS, 0, &*buffer.begin(), result);
        if (result < 0) {
          std::ostringstream error;
          error << "proc_pidinfo() failed to fill buffer: " << result;
          throw std::runtime_error(error.str());
        }
        return result / PROC_PIDLISTFD_SIZE;
      }

      size_t
      get_max_fds() const {
        rlimit limit;
        int result = getrlimit(RLIMIT_NOFILE, &limit); 
        return limit.rlim_cur;
      }

    private: // data members
      const pid_t pid_;
      const double starttime_;

    };
#endif // __APPLE__
  } /* namespace impl */

  impl::ProcessCollector* global_process_collector = nullptr;

  void install_process_exports() {
#ifdef __APPLE__
    using os_collector = impl::MacOSProcessCollector;
#else
    using os_collector = impl::LinuxProcessCollector;
#endif
    global_process_collector = new os_collector();
  }
} /* namespace prometheus */
