/*
 * Copyright (c) 2015-2017 Andrei Gudkov <gudokk@gmail.com>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */


#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>
#include <locale.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdarg.h>
#include <limits.h>
#include <float.h>

#include <unistd.h>
#include <sys/sysmacros.h> // major, minor
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <getopt.h>
#include <linux/fs.h>
#include <dirent.h>
#include <linux/aio_abi.h>
#include <sys/syscall.h>
#include <mntent.h>
#ifndef NDEBUG
#  include <execinfo.h>
#endif



/******************************* MACRO DEFINITIONS ************************************/

#define VER_MAJOR 1
#define VER_MINOR 9
#define VER_DATE "June 2019"

#define arrlen(arr) (int64_t) (sizeof(arr) / sizeof((arr)[0]))

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define max3(a, b, c) max((a), max((b), (c)))

#define to_double(arg) ((double) (arg))
#define to_int64(arg)  ((int64_t) (arg))
#define to_uint64(arg) ((uint64_t) (arg))
#define to_int32(arg)  ((int32_t) (arg))
#define to_uint32(arg) ((uint32_t) (arg))

#define deref(arg)         ((arg) ? (arg) : "(null)")
#define deref2(arg1, arg2) ((arg1) ? deref(arg1->arg2) : "(null)")

#define get_base_pointer(self, type_name, member_name) \
  (type_name*) (((void*) (self)) - offsetof(type_name, member_name))

/* redefine assert to dump stacktrace */
#ifdef assert
#  undef assert
#endif
#ifdef NDEBUG
#  define assert(expr)
#else
#  define assert(expr) \
     if (!(expr)) { \
       fprintf(stderr, "%s:%d %s: Assertion `%s' failed.\n", __FILE__, __LINE__, __FUNCTION__, #expr); \
       void* buf[128]; \
       int length = backtrace(buf, arrlen(buf)); \
       backtrace_symbols_fd(buf, length, fileno(stderr)); \
       exit(EXIT_FAILURE); \
     }
#endif

/* logging functions */
#define report(msg, ...) fprintf(stdout, (msg), ##__VA_ARGS__);
#define warn(msg, ...) fprintf(stdout, "(WARN) "msg, ##__VA_ARGS__);
#define die(msg, ...) { \
  fprintf(stderr, "drvperf: "msg, ##__VA_ARGS__); \
  exit(EXIT_FAILURE); \
}
#define die_help(msg, ...) { \
  fprintf(stderr, "drvperf: "msg, ##__VA_ARGS__); \
  fprintf(stderr, "Call `drvperf --help' for list of options.\n"); \
  exit(EXIT_FAILURE); \
}

inline static bool is_power2(int64_t arg) {
  return (arg & (arg - 1)) == 0;
}

inline static int64_t abs64(int64_t arg) {
  return arg >= 0 ? arg : -arg;
}


/******************************* SYSCONF ***********************************/

static int64_t sc_page_size = -1;
static int64_t sc_iov_max = -1;

static void sc_query_sysconf() {
  sc_page_size = sysconf(_SC_PAGESIZE);
  if (sc_page_size == -1) {
    die("sysconf(_SC_PAGESIZE)\n");
  }
  
  sc_iov_max = sysconf(_SC_IOV_MAX);
  if (sc_iov_max == -1) {
    die("sysconf(_SC_IOV_MAX)\n");
  }
}

static void sc_dump_sysconf_vars() {
  report("Sysconf:\n");
  report("  page size ...  %"PRId64"\n", sc_page_size);
  report("  iov max .....  %"PRId64"\n", sc_iov_max);
  report("\n");
}
 

/************************** SETTINGS TYPES *********************************/

/* operation_t */

enum operation_id {
  OP_READ = 0,
  OP_WRITE
};

struct operation_t {
  enum operation_id id;
  const char* name;
  int open_mode;        // complies with open(2)
  uint16_t iocb_opcode; // iocb.aio_lio_opcode
};
 
static const struct operation_t OPERATIONS[] = {
  [OP_READ]  = {OP_READ, "read",  O_RDONLY, IOCB_CMD_PREAD},
  [OP_WRITE] = {OP_WRITE, "write", O_WRONLY, IOCB_CMD_PWRITE}
};


/* field_t */

enum field_id {
  FLD_BASE_OFFSET = 0, // first of two IO offsets (when pair of jumps is made)
  FLD_OFFSET,          // IO offset
  FLD_ABSDELTA,        // abs(FLD_OFFSET - FLD_BASE_OFFSET)
  FLD_PROBE_LENGTH,    // IO length
  FLD_MILLIS           // IO operation time in milliseconds
};

struct field_t {
  enum field_id id;
  const char* name; // name as to appear in TSV header
};

static const struct field_t FIELDS[] = {
  [FLD_BASE_OFFSET]  = { FLD_BASE_OFFSET,  "base_offset"},
  [FLD_OFFSET]       = { FLD_OFFSET,       "offset"},
  [FLD_ABSDELTA]     = { FLD_ABSDELTA,     "absdelta"},
  [FLD_PROBE_LENGTH] = { FLD_PROBE_LENGTH, "probe_length"},
  [FLD_MILLIS]       = { FLD_MILLIS,       "millis"}
};


/* test_t */

enum test_id {
  TN_SEQUENTIAL_READ = 0,
  TN_SEQUENTIAL_WRITE,
  TN_RANDOM_READ,
  TN_RANDOM_WRITE,
  TN_RANDOM_DELTA_READ,
  TN_FULLSTROKE,
  TN_TRACKTOTRACK,
  TN_CONCURRENCY_READ,
  TN_CONCURRENCY_WRITE
};

typedef void (*testfunc_t)();
static void seq_run_sequential_test();
static void rnd_run_random_test();
static void rd_run_random_delta_test();
static void hm_run_fullstroke_test();
static void hm_run_tracktotrack_test();
static void cnc_run_concurrency_test();

// standard set of fields, most of tests use it
static const struct field_t* STD_FIELDS[] = {
  &FIELDS[FLD_OFFSET],
  &FIELDS[FLD_PROBE_LENGTH],
  &FIELDS[FLD_MILLIS],
  NULL
};

/* used for tests where pair of jumps is made: between ${base_offset} and ${offset} */
static const struct field_t* DLT_FIELDS[] = {
  &FIELDS[FLD_BASE_OFFSET],
  &FIELDS[FLD_OFFSET],
  &FIELDS[FLD_ABSDELTA],
  &FIELDS[FLD_PROBE_LENGTH],
  &FIELDS[FLD_MILLIS],
  NULL
};


struct test_t {
  enum test_id id;
  const char* name;
  const struct operation_t* operation;
  int64_t default_probe_count;
  int64_t default_probe_length;
  testfunc_t func;
  const struct field_t** fields;
};

static const struct test_t TESTS[] = {
  [TN_SEQUENTIAL_READ] = {
    .id                   = TN_SEQUENTIAL_READ,
    .name                 = "seqread",
    .operation            = &OPERATIONS[OP_READ],
    .default_probe_count  = 100,
    .default_probe_length = 128*1024*1024,
    .func                 = &seq_run_sequential_test,
    .fields               = STD_FIELDS
  },
  [TN_SEQUENTIAL_WRITE] = {
    .id                   = TN_SEQUENTIAL_WRITE,
    .name                 = "seqwrite",
    .operation            = &OPERATIONS[OP_WRITE],
    .default_probe_count  = 100,
    .default_probe_length = 128*1024*1024,
    .func                 = &seq_run_sequential_test,
    .fields               = STD_FIELDS
  },
  [TN_RANDOM_READ] = {
    .id                   = TN_RANDOM_READ,
    .name                 = "rndread",
    .operation            = &OPERATIONS[OP_READ],
    .default_probe_count  = 20*1000,
    .default_probe_length = -1,
    .func                 = &rnd_run_random_test,
    .fields               = STD_FIELDS
  },
  [TN_RANDOM_WRITE] = {
    .id                   = TN_RANDOM_WRITE,
    .name                 = "rndwrite",
    .operation            = &OPERATIONS[OP_WRITE],
    .default_probe_count  = 20*1000,
    .default_probe_length = -1,
    .func                 = &rnd_run_random_test,
    .fields               = STD_FIELDS
  },
  [TN_RANDOM_DELTA_READ] = {
    .id                   = TN_RANDOM_DELTA_READ,
    .name                 = "rnddeltaread",
    .operation            = &OPERATIONS[OP_READ],
    .default_probe_count  = 2*1000,
    .default_probe_length = -1,
    .func                 = &rd_run_random_delta_test,
    .fields               = DLT_FIELDS
  },
  [TN_FULLSTROKE] = {
    .id                   = TN_FULLSTROKE,
    .name                 = "fullstroke",
    .operation            = &OPERATIONS[OP_READ],
    .default_probe_count  = 5*1000,
    .default_probe_length = -1,
    .func                 = &hm_run_fullstroke_test,
    .fields               = DLT_FIELDS
  },
  [TN_TRACKTOTRACK] = {
    .id                   = TN_TRACKTOTRACK,
    .name                 = "tracktotrack",
    .operation            = &OPERATIONS[OP_READ],
    .default_probe_count  = 5*1000,
    .default_probe_length = -1,
    .func                 = &hm_run_tracktotrack_test,
    .fields               = DLT_FIELDS
  },
  [TN_CONCURRENCY_READ] = {
    .id                   = TN_CONCURRENCY_READ,
    .name                 = "cncread",
    .operation            = &OPERATIONS[OP_READ],
    .default_probe_count  = 5*1000,
    .func                 = &cnc_run_concurrency_test,
    .fields               = STD_FIELDS
  },
  [TN_CONCURRENCY_WRITE] = {
    .id                   = TN_CONCURRENCY_WRITE,
    .name                 = "cncwrite",
    .operation            = &OPERATIONS[OP_WRITE],
    .default_probe_count  = 5*1000,
    .func                 = &cnc_run_concurrency_test,
    .fields               = STD_FIELDS
  }
};


/* cache_policy_t */

enum cache_policy_id {
  CP_KEEP = 0,    // don't do anything special
  CP_DROP,        // free buffers and caches before test is started
  CP_BYPASS,      // use direct IO
};

struct cache_policy_t {
  enum cache_policy_id id;
  const char* name;
  int open_flags;
};
  
static const struct cache_policy_t CACHE_POLICY[] = {
  [CP_KEEP]   = {CP_KEEP,   "keep",   0},
  [CP_DROP]   = {CP_DROP,   "drop",   0},
  [CP_BYPASS] = {CP_BYPASS, "bypass", O_DIRECT}
};


/* sync_policy_t */

enum sync_policy_id {
  SP_NONE = 0,
  SP_SYNC,
  SP_DSYNC
};

struct sync_policy_t {
  enum sync_policy_id id;
  const char* name;
  int open_flags;
};

static const struct sync_policy_t SYNC_POLICY[] = {
  [SP_NONE]  = {SP_NONE,  "none",  0},
  [SP_SYNC]  = {SP_SYNC,  "sync",  O_SYNC},
  [SP_DSYNC] = {SP_DSYNC, "dsync", O_DSYNC}
};


/* method_t */

enum method_id {
  M_AUTO,
  M_BIO,    // ordinal blocking IO
  M_KAIO    // kernel async IO (io_submit(2))
};

struct method_t {
  enum method_id id;
  const char* name;
};

static const struct method_t METHODS[] = {
  [M_BIO] =  {M_BIO,  "bio"},
  [M_KAIO] = {M_KAIO, "kaio"},
  [M_AUTO] = {M_AUTO, "auto"}
};

/******************************* SETTINGS VARIABLES **************************************/

static const struct test_t* test = NULL;
static char* target_path = NULL;
static int64_t probe_count = -1;
static int64_t probe_length = -1;
static int64_t offset_alignment = -1;
static const struct cache_policy_t* cache_policy = &CACHE_POLICY[CP_BYPASS];
static bool debug = false;
static int64_t concurrent = 1;           // number of concurrent requests to make
static int64_t window_begin = -1;        // absolute values in bytes
static int64_t window_end = -1;          //
static int64_t window_length = -1;       //
static double window_begin_rel = NAN;    // relative to file length
static double window_end_rel = NAN;      //
static double window_length_rel = NAN;   //
static const char* dump_file = NULL;
static bool force = false;               // bypass safety checks
static int64_t maxcylsize = -1;
static const struct method_t* method = &METHODS[M_AUTO];
static const struct sync_policy_t* sync_policy = &SYNC_POLICY[SP_SYNC];
static int64_t max_buffer_size = 128*1024*1024;
static int64_t rndseed = -1;

static void dump_settings_vars() {
  report("Test settings:\n");
  report("  test name ..........  %s\n",        deref2(test, name));
  report("  target path ........  %s\n",        deref(target_path));
  report("  probe count ........  %"PRId64"\n", probe_count);
  report("  probe length .......  %"PRId64"\n", probe_length);
  report("  offset alignment ...  %"PRId64"\n", offset_alignment);
  report("  cache policy .......  %s\n",        deref2(cache_policy, name));
  report("  debug ..............  %s\n",        debug ? "yes" : "no");
  report("  concurrent .........  %"PRId64"\n", concurrent);
  report("  window begin .......  %"PRId64"\n", window_begin);
  report("  window end .........  %"PRId64"\n", window_end);
  report("  window length ......  %"PRId64"\n", window_length);
  report("  window begin rel ...  %f\n",        window_begin_rel);
  report("  window end rel .....  %f\n",        window_end_rel);
  report("  window length rel ..  %f\n",        window_length_rel);
  report("  dump file ..........  %s\n",        deref(dump_file));
  report("  force ..............  %s\n",        force ? "yes" : "no");
  report("  maxcylsize..........  %"PRId64"\n", maxcylsize);
  report("  method .............  %s\n",        deref2(method, name));
  report("  sync policy ........  %s\n",        deref2(sync_policy, name));
  report("  max buffer size ....  %"PRId64"\n", max_buffer_size);
  report("  rndseed ............  %"PRId64"\n", rndseed);
  report("\n");
}
 

/****************************** MEMORY LIB WRAPPERS **********************************/

inline static void* dymalloc(size_t size) {
  void* ptr = malloc(size);
  if (!ptr) {
    die("malloc(size=%"PRId64")\n", size);
  }
  return ptr;
}

/* malloc aligned */
inline static void* dymalloca(size_t size, size_t alignment) {
  void* ptr = NULL;
  int r = posix_memalign(&ptr, alignment, size);
  if (r) {
    die("posix_memalign(size=%"PRId64", alignment=%"PRId64"): %s\n", size, alignment, strerror(r));
  }
  return ptr;
}

inline static void* dyrealloc(void* ptr, size_t size) {
  ptr = realloc(ptr, size);
  if (!ptr) {
    die("realloc(size=%"PRId64")\n", size);
  }
  return ptr;
}

inline static void dyfree(void* ptr) {
  free(ptr);
}

inline static char* dystrdup(const char* str) {
  char* ptr = strdup(str);
  if (!ptr) {
    die("strdup: %s\n", strerror(errno));
  }
  return ptr;
}


/**************************** TSV WRITER ************************************/

struct tsv_t {
  int fd;
  char* buf;
  int buf_len;
  int buf_pos;
  int field_no;
};

static void tsv_open(struct tsv_t* tsv, const char* path) {
  tsv->fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0666);
  if (tsv->fd == -1) {
    die("Failed to open tsv file `%s': %s\n", path, strerror(errno));
  }
  tsv->buf_len = 512*1024;
  tsv->buf = dymalloc(tsv->buf_len);
  tsv->buf_pos = 0;
  tsv->field_no = 0;
}

static void tsv_flush(struct tsv_t* tsv) {
  int offset = 0;
  while (offset < tsv->buf_pos) {
    int count = write(tsv->fd, tsv->buf + offset, tsv->buf_pos - offset); 
    if (count == -1) {
      die("Error writing tsv: %s\n", strerror(errno));
    }
    offset += count;
  }
  tsv->buf_pos = 0;
}

static void tsv_close(struct tsv_t* tsv) {
  tsv_flush(tsv);
  close(tsv->fd);
  free(tsv->buf);
}

static void tsv_write_fmt(struct tsv_t* tsv, const char* format, ...) {
  va_list args;

  while (true) {
    int free = tsv->buf_len - tsv->buf_pos;

    va_start(args, format);
    int count = vsnprintf(tsv->buf + tsv->buf_pos, free, format, args);
    va_end(args);

    if (count == -1) {
      die("Failed to write tsv: vsnprintf\n");
    } else if (count < free) {
      tsv->buf_pos += count;
      break;
    } else if (count <= tsv->buf_len) {
      tsv_flush(tsv);
    } else {
      die("Failed to write tsv: buffer overflow\n");
    }
  }
}

inline static void tsv_write_double(struct tsv_t* tsv, double value) {
  tsv_write_fmt(tsv, (tsv->field_no++ == 0 ? "%f" : "\t%f"), value);
}

inline static void tsv_write_int64(struct tsv_t* tsv, int64_t value) {
  tsv_write_fmt(tsv, (tsv->field_no++ == 0 ? "%"PRId64 : "\t%"PRId64), value);
}

inline static void tsv_write_string(struct tsv_t* tsv, const char* str) {
  for (const char* c = str; *c; c++) {
    if (*c == '\t' || *c == '\r' || *c == '\n') {
      die("tsv illegal character in string");
    }
  }
  tsv_write_fmt(tsv, (tsv->field_no++ == 0 ? "%s" : "\t%s"), str);
}

inline static void tsv_newline(struct tsv_t* tsv) {
  tsv->field_no = 0;
  tsv_write_fmt(tsv, "\n");
}


/************************** DIR LISTER **********************************/

struct dir_lister_t {
  char path[PATH_MAX];
  DIR* dir;
  struct dirent buffer;
  struct dirent* entry;
};

static void dl_opendir(struct dir_lister_t* dl, const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vsnprintf(dl->path, sizeof(dl->path), fmt, args);
  va_end(args);
  
  dl->dir = opendir(dl->path);
  if (!dl->dir) {
    die("opendir(%s): %s\n", dl->path, strerror(errno));
  }
}

static void dl_closedir(struct dir_lister_t* dl) {
  closedir(dl->dir);
}

static bool dl_readdir(struct dir_lister_t* dl) {
  while (true) {
    int r = readdir_r(dl->dir, &dl->buffer, &dl->entry);
    if (r) {
      die("readdir_r(%s): %s\n", dl->path, strerror(errno));
    }
    if (dl->entry == NULL) {
      return false;
    }
    if (dl->entry->d_name[0] != '.') {
      return true;
    }
  }
}


/****************************** RANDOM **********************************/

static uint32_t rnd_state[32];
static uint32_t rnd_offset;

static void rnd_seed(uint32_t seed) {
  if (seed == 0) {
    die("Zero random seed is not allowed");
  }
  for (int i = 0; i < 32; i++) {
    rnd_state[i] = seed;
  }
  rnd_offset = 0;
}

/* 
 * Implementation of WELL1024a.
 * 
 * Algorithm description and parameters are taken from following article:
 * "Improved Long-Period Generators Based on Linear Recurrences Modulo 2"
 * F. Panneton, P. L'Ecuyer and M. Matsumoto
 * http://www.iro.umontreal.ca/~lecuyer/myftp/papers/lfsr04.pdf
 * 
 * Implementation was tested by "dieharder" 3.31.1
 * Robert G. Brown
 * http://www.phy.duke.edu/~rgb/General/dieharder.php
 */
static uint32_t rnd_u32() {
# define v(i) rnd_state[(rnd_offset+(i)) & 0x1f]
  uint32_t z0 = v(31);
  uint32_t z1 = v(0) ^ v(3) ^ (v(3) >> 8);
  uint32_t z2 = v(24) ^ (v(24) << 19) ^ v(10) ^ (v(10) << 14);
  uint32_t z4 = z0 ^ (z0 << 11) ^ z1 ^ (z1 << 7) ^ z2 ^ (z2 << 13);

  rnd_offset = (rnd_offset-1) & 0x1f;
  v(1) = z1 ^ z2;
  v(0) = z4;
# undef v

  return z4;
}

inline static uint8_t rnd_u8() {
  return (uint8_t) (rnd_u32() & 0xff);
}

inline static uint64_t rnd_u64() {
  return to_uint64(rnd_u32()) << 32 | to_uint64(rnd_u32());
}

/*
 * Genereate random value in range ${first}..${last} inclusively.
 */
inline static uint64_t rnd_u64_range(uint64_t first, uint64_t last) {
  assert(last >= first);
  
  if (first == 0 && last == UINT64_MAX) {
    return rnd_u64();
  }
  
  uint64_t count = last - first + 1;
  uint64_t value;
  do {
    value = rnd_u64();
  } while (value >= (UINT64_MAX / count * count));
  
  return first + (value % count);
}

static void rnd_fill_random(char* ptr, int64_t length) {
  int64_t left = length;
  char* dst = ptr;
  
  while (left >= to_int64(sizeof(int64_t))) {
    *((uint64_t*) dst) = rnd_u64();
    dst += sizeof(int64_t);
    left -= sizeof(int64_t);
  }
  
  while (left > 0) {
    *ptr = (char) rnd_u8();
    ptr++;
    left--;
  }
}


/******************** MISSING SYSCALL WRAPPERS *****************************/

inline static int io_setup(unsigned nr_events, aio_context_t *ctx_idp) {
  return syscall(__NR_io_setup, nr_events, ctx_idp);
}
  
inline static int io_destroy(aio_context_t ctx_id) {
  return syscall(__NR_io_destroy, ctx_id);
}
 
inline static int io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp) {
  return syscall(__NR_io_submit, ctx_id, nr, iocbpp);
}
 
inline static int io_getevents(aio_context_t ctx_id, long min_nr, long nr, 
                            struct io_event *events, struct timespec *timeout) {
   return syscall(__NR_io_getevents, ctx_id, min_nr, nr, events, timeout);
}

inline static int io_cancel(aio_context_t ctx_id, struct iocb *iocb, struct io_event *result) {
  return syscall(__NR_io_cancel, ctx_id, iocb, *result);
}


/************************** BLOCK DEVICE REGISTRY *******************************/

struct bdev_t;

/* block dev list */
struct bdl_t {
  struct bdev_t** elements;
  int64_t length;
};

#define bdl_null { NULL, 0 }

struct bdev_t {
  dev_t majmin;
  char* name;
  char* mount_point;
  
  int64_t physical_sector_size;
  int64_t logical_sector_size;
  int64_t minimal_io_size;
  int64_t optimal_io_size;
  int64_t size;
  int64_t start; // (partitions only) start relative to parent device
  
  // partitions 
  struct bdev_t* pt_parent; // if present then current blockdev is partition
  struct bdl_t pt_children; // partitions inside current blockdev
  
  // raid
  struct bdl_t md_slaves;   // if current blockdev is RAID then it is built atop number of ${md_slaves}
  struct bdev_t* md_master; // if present then current blockdev is used to build RAID upon
};

static void bdl_list_all_devices(struct bdl_t* bdl);
static struct bdev_t* bdl_query_settings(const char* name);
static void bdl_add_to_list(struct bdl_t* bdl, struct bdev_t* bdev);
static struct bdev_t* bdl_find(struct bdl_t* bdl, dev_t majmin);
static void bdl_link_mdslaves(struct bdl_t* bdl, struct bdev_t* bdev);
static void bdl_link_partitions(struct bdl_t* bdl, struct bdev_t* bdev);
static int64_t bdl_read_int64(const char* path_fmt, ...);
static dev_t bdl_query_majmin(const char* devname);
static int64_t bdl_query_physical_sector_size(const char* devname);
static int64_t bdl_query_logical_sector_size(const char* devname);
static int64_t bdl_query_minimal_io_size(const char* devname);
static int64_t bdl_query_optimal_io_size(const char* devname);
static int64_t bdl_query_size(const char* devname);
static int64_t bdl_query_start(const char* devname);
static char* bdl_find_mount_point(dev_t majmin);
static void bdl_dump(struct bdev_t* bdev);
static void bdl_dump_all(struct bdl_t* bdl);
static bool bdl_exists(const char* devname);
static void bdl_deinit(struct bdl_t* bdl);
static char* bdl_join_names(struct bdl_t* bdl);
static void bdl_inherit_settings(struct bdev_t* bdev);
static void bdl_check_settings(struct bdev_t* bdev);

static const char* const SYSFS_PATH_BLOCK = "/sys/class/block";

static struct bdev_t* bdl_query_settings(const char* name) {
  struct bdev_t* bdev = dymalloc(sizeof(struct bdev_t));
  
  bdev->name = dystrdup(name);
  
  bdev->majmin = bdl_query_majmin(name);
  bdev->physical_sector_size = bdl_query_physical_sector_size(name);
  bdev->logical_sector_size = bdl_query_logical_sector_size(name);
  bdev->minimal_io_size = bdl_query_minimal_io_size(name);
  bdev->optimal_io_size = bdl_query_optimal_io_size(name);
  bdev->size = bdl_query_size(name);
  bdev->start = bdl_query_start(name);
  
  bdev->mount_point = bdl_find_mount_point(bdev->majmin);
  
  bdev->pt_parent = NULL;
  bdev->pt_children = (struct bdl_t) bdl_null;
  bdev->md_master = NULL;
  bdev->md_slaves = (struct bdl_t) bdl_null;
  
  return bdev;
}
  
static void bdl_deinit(struct bdl_t* bdl) {
  for (int64_t i = 0; i < bdl->length; i++) {
    dyfree(bdl->elements[i]->name);
    dyfree(bdl->elements[i]->mount_point);
    dyfree(bdl->elements[i]->pt_children.elements);
    dyfree(bdl->elements[i]->md_slaves.elements);
    dyfree(bdl->elements[i]);
  }
  dyfree(bdl->elements);
}

/*
 * Searches for mount path of given block device.
 * Caller is responsible for returned string deallocation.
 */
static char* bdl_find_mount_point(dev_t majmin) {
  FILE* f = setmntent(_PATH_MOUNTED, "r");
  if (!f) {
    die("setmntent(%s)\n", _PATH_MOUNTED);
  }
  
  struct mntent* me;
  char* mount_point = NULL;
  while ((me = getmntent(f)) != NULL) {
    struct stat st;
    if (stat(me->mnt_fsname, &st) == -1) {
      continue;
    }
    
    if ((st.st_mode & S_IFMT) != S_IFBLK) {
      continue;
    }
    
    if (st.st_rdev == majmin) {
      mount_point = dystrdup(me->mnt_dir);
      break;
    }
  }
  
  endmntent(f);
  
  return mount_point;
}


static void bdl_add_to_list(struct bdl_t* bdl, struct bdev_t* bdev) {
  if (bdl->length == 0) {
    bdl->elements = dymalloc(sizeof(struct bdev_t*));
  } else {
    bdl->elements = dyrealloc(bdl->elements, sizeof(struct bdev_t*) * (bdl->length + 1));
  }
  bdl->elements[bdl->length++] = bdev;
}

static void bdl_link_partitions(struct bdl_t* bdl, struct bdev_t* bdev) {
  struct dir_lister_t lister;
  dl_opendir(&lister, "%s/%s", SYSFS_PATH_BLOCK, bdev->name);
  while (dl_readdir(&lister)) {
    if (bdl_exists(lister.entry->d_name)) {
      dev_t majmin = bdl_query_majmin(lister.entry->d_name);
      struct bdev_t* child = bdl_find(bdl, majmin);
      if (child) {
        child->pt_parent = bdev;
        bdl_add_to_list(&bdev->pt_children, child);
      }
    }
  }
  dl_closedir(&lister);
}
  
static void bdl_link_mdslaves(struct bdl_t* bdl, struct bdev_t* bdev) {
  struct dir_lister_t lister;
  dl_opendir(&lister, "%s/%s/holders", SYSFS_PATH_BLOCK, bdev->name);
  while (dl_readdir(&lister)) {
    if (bdl_exists(lister.entry->d_name)) {
      dev_t majmin = bdl_query_majmin(lister.entry->d_name);
      struct bdev_t* master = bdl_find(bdl, majmin);
      if (master) {
        bdev->md_master = master;
        bdl_add_to_list(&master->md_slaves, bdev);
      }
    }
  }
  dl_closedir(&lister);
}

static struct bdev_t* bdl_find(struct bdl_t* bdl, dev_t majmin) {
  for (int i = 0; bdl->elements[i]; i++) {
    if (bdl->elements[i]->majmin == majmin) {
      return bdl->elements[i];
    }
  }
  return NULL;
}

/*
 * Queries sysfs for info on all installed block devices.
 */
static void bdl_list_all_devices(struct bdl_t* bdl) {
  
  // enumerate devices
  struct dir_lister_t dl;
  dl_opendir(&dl, SYSFS_PATH_BLOCK);
  while (dl_readdir(&dl)) {
    bdl_add_to_list(bdl, bdl_query_settings(dl.entry->d_name));
  }
  dl_closedir(&dl);
  
  // link devices together
  for (int64_t i = 0; i < bdl->length; i++) {
    bdl_link_partitions(bdl, bdl->elements[i]);
    bdl_link_mdslaves(bdl, bdl->elements[i]);
  }
  
  // inherit missing settings from parent devices
  for (int64_t i = 0; i < bdl->length; i++) {
    bdl_inherit_settings(bdl->elements[i]);
  }
  
  // final checks
  for (int64_t i = 0; i < bdl->length; i++) {
    bdl_check_settings(bdl->elements[i]);
  }
}

static void bdl_inherit_settings(struct bdev_t* bdev) {
  struct bdev_t* curr = bdev;
  while (curr->pt_parent) {
    curr = curr->pt_parent;
    
    if (bdev->logical_sector_size == -1) {
      bdev->logical_sector_size = curr->logical_sector_size;
    }
    if (bdev->physical_sector_size == -1) {
      bdev->physical_sector_size = curr->physical_sector_size;
    }
    if (bdev->minimal_io_size == -1) {
      bdev->minimal_io_size = curr->minimal_io_size;
    }
    if (bdev->optimal_io_size == -1) {
      bdev->optimal_io_size = curr->optimal_io_size;
    }
  }
}

static void bdl_check_settings(struct bdev_t* bdev) {
  if (bdev->logical_sector_size == -1) {
    die("Can't detect logical sector size for %s\n", bdev->name);
  }
  if (bdev->physical_sector_size == -1) {
    die("Can't detect physical sector size for %s\n", bdev->name);
  }
}

/* Returns comma separated list of block devices names */
static char* bdl_join_names(struct bdl_t* bdl) {
  int len = 0;
  for (int64_t i = 0; i < bdl->length; i++) {
    if (i > 0) {
      len += 1;
    }
    len += strlen(bdl->elements[i]->name);
  }
  len += 1;
  
  char* str = dymalloc(len);
  int off = 0;
  for (int64_t i = 0; i < bdl->length; i++) {
    if (i > 0) {
      str[off++] = ',';
    }
    for (int j = 0; bdl->elements[i]->name[j] != '\0'; j++) {
      str[off++] = bdl->elements[i]->name[j];
    }
  }
  str[off] = '\0';
  
  return str;
}

static void bdl_dump(struct bdev_t* bdev) {
  char* md_slaves_str = bdl_join_names(&bdev->md_slaves);
  char* pt_children_str = bdl_join_names(&bdev->pt_children);
  
  report("Block device:\n");
  report("  name ...................  %s\n",        deref(bdev->name));
  report("  mount point ............  %s\n",        deref(bdev->mount_point));
  report("  dev no .................  %d:%d\n",     major(bdev->majmin), minor(bdev->majmin));
  report("  physical sector size ...  %"PRId64"\n", bdev->physical_sector_size);
  report("  logical sector size ....  %"PRId64"\n", bdev->logical_sector_size);
  report("  minimal io size ........  %"PRId64"\n", bdev->minimal_io_size);
  report("  optimal io size ........  %"PRId64"\n", bdev->optimal_io_size);
  report("  size ...................  %"PRId64"\n", bdev->size);
  report("  start ..................  %"PRId64"\n", bdev->start);
  report("  (part) parent ..........  %s\n",        deref2(bdev->pt_parent, name));
  report("  (part) children ........  [%s]\n",      pt_children_str);
  report("  (md) master ............  %s\n",        deref2(bdev->md_master, name));
  report("  (md) slaves ............  [%s]\n",      md_slaves_str);
  report("\n");
  
  dyfree(md_slaves_str);
  dyfree(pt_children_str);
}

static void bdl_dump_all(struct bdl_t* bdl) {
  for (int64_t i = 0; i < bdl->length; i++) {
    report("%"PRId64"/%"PRId64" ", i+1, bdl->length);
    bdl_dump(bdl->elements[i]);
  }
}

/*
 * Reads int64 from path given by ${path_fmt} and following arguments.
 * If file doesn't exist, returns -1, other errors are fatal.
 */
static int64_t bdl_read_int64(const char* path_fmt, ...) {
  char path[PATH_MAX];
  va_list args;
  va_start(args, path_fmt);
  vsnprintf(path, sizeof(path), path_fmt, args);
  va_end(args);
  
  FILE* file = fopen(path, "r");
  if (!file) {
    if (errno == ENOENT) {
      return -1;
    } else {
      die("fopen(%s): %s\n", path, strerror(errno));
    }
  }
  int64_t value;
  if (fscanf(file, "%"SCNd64, &value) != 1) {
    die("%s has unexpected format\n", path);
  }
  fclose(file);
  return value;
}

static int64_t bdl_query_physical_sector_size(const char* devname) {
  int64_t value = bdl_read_int64("%s/%s/queue/physical_block_size", SYSFS_PATH_BLOCK, devname);
  return value > 0 ? value : -1;
}

static int64_t bdl_query_logical_sector_size(const char* devname) {
  int64_t value = bdl_read_int64("%s/%s/queue/logical_block_size", SYSFS_PATH_BLOCK, devname);
  return value > 0 ? value : -1;
}

static int64_t bdl_query_minimal_io_size(const char* devname) {
  int64_t value = bdl_read_int64("%s/%s/queue/minimum_io_size", SYSFS_PATH_BLOCK, devname);
  return value > 0 ? value : -1;
}

static int64_t bdl_query_optimal_io_size(const char* devname) {
  int64_t value = bdl_read_int64("%s/%s/queue/optimal_io_size", SYSFS_PATH_BLOCK, devname);
  return value > 0 ? value : -1;
}

static int64_t bdl_query_size(const char* devname) {
  int64_t value = bdl_read_int64("%s/%s/size", SYSFS_PATH_BLOCK, devname);
  // size is always in units of 512
  return (value >= 0) ? (value * 512) : -1; 
}

static int64_t bdl_query_start(const char* devname) {
  int64_t value = bdl_read_int64("%s/%s/start", SYSFS_PATH_BLOCK, devname);
  // start is always in units of 512
  return (value >= 0) ? (value * 512) : -1; 
}

static bool bdl_exists(const char* devname) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/%s/dev", SYSFS_PATH_BLOCK, devname);
  return (access(path, F_OK) == 0);
}

static dev_t bdl_query_majmin(const char* devname) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/%s/dev", SYSFS_PATH_BLOCK, devname);
  
  FILE* file = fopen(path, "r");
  if (!file) {
    die("fopen(%s): %s\n", path, strerror(errno));
  }
  
  unsigned int v_major;
  unsigned int v_minor;
  if (fscanf(file, "%u:%u\n", &v_major, &v_minor) != 2) {
    die("%s has invalid format\n", path);
  }
  
  fclose(file);
  
  return makedev(v_major, v_minor);
}


/**************************** PROBE ARRAY ************************************/

struct long_probe_t {
  int64_t offset;        // file offset
  int64_t start_time;    // nanoseconds
  int64_t finish_time;   // nanoseconds
  int64_t base_offset;   // first of two offsets (valid for selected tests only)
};

struct __attribute__((packed)) probe_t {
  int64_t offset:56;
  int64_t nanoes:48;
  int64_t base_offset:56;
};

/* probe array */
struct pba_t {
  struct probe_t* elements;
  int64_t capacity;
  int64_t length;
  
  int64_t glb_start_time;   // smalleset ${start_time} among all probes
  int64_t glb_finish_time;  // largest ${finish_time} among all probes
};

static void pba_init(struct pba_t* pba, int64_t capacity) {
  pba->capacity = capacity;
  pba->length = 0;
  pba->elements = dymalloc(sizeof(struct probe_t) * capacity);
  
  // better to pagefault now rather than during test run
  bzero(pba->elements, sizeof(struct probe_t) * capacity);
}

static void pba_deinit(struct pba_t* pba) {
  dyfree(pba->elements);
}

inline static void pba_add(struct pba_t* pba, struct long_probe_t* probe) {
  assert(pba->length < pba->capacity);
  assert(probe->finish_time >= probe->start_time);
  assert(probe->offset >= 0);
  
  pba->elements[pba->length++] = (struct probe_t) {
    .nanoes = probe->finish_time - probe->start_time,
    .offset = probe->offset,
    .base_offset = probe->base_offset
  };
  if (pba->length > 1) {
    pba->glb_start_time = min(pba->glb_start_time, probe->start_time);
    pba->glb_finish_time = max(pba->glb_finish_time, probe->finish_time);
  } else {
    pba->glb_start_time = probe->start_time;
    pba->glb_finish_time = probe->finish_time;
  }
}

inline static void pba_clear(struct pba_t* pba) {
  pba->length = 0;
}

/*
 * Rearranges ${probe},${offset},${length} in such way that ${limit} largest values are located in the 
 * rightmost part of the array and are sorted by ${probe_t.nanoes}.
 */
static void pba_partial_qsort(struct pba_t* pba, int64_t offset, int64_t length, int64_t limit) {
  if (length <= 1) {
    return;
  }

  int64_t pivot_nanoes = pba->elements[offset + (length/2)].nanoes;
  int64_t left = offset;
  int64_t right = offset + length - 1;
  while (left <= right) {
    while (pba->elements[left].nanoes < pivot_nanoes) {
      left++;
    }
    while (pba->elements[right].nanoes > pivot_nanoes) {
      right--;
    }
    if (left <= right) {
      struct probe_t tmp = pba->elements[left];
      pba->elements[left] = pba->elements[right];
      pba->elements[right] = tmp;
      left++;
      right--;
    }
  }

  // ...,right,left,... OR ...,right,x,left,...
  int64_t l_length = right - offset + 1;
  int64_t m_length = left - right - 1;
  int64_t r_length = length - (left - offset);
  pba_partial_qsort(pba, left, r_length, limit); // right subarray
  if (limit-r_length-m_length > 0) {
    pba_partial_qsort(pba, offset, l_length, limit-r_length-m_length); // left subarray
  }
}

/*
 * Randomly shuffles given region.
 */
static void pba_shuffle(struct pba_t* pba, int64_t offset, int64_t length) {
  assert(offset >= 0 && offset < pba->length);
  assert(length >= 0 && offset + length <= pba->length);
  
  for (int64_t i = length-1; i >= 1; i--) {
    int64_t j = rnd_u64_range(0, i);
    if (j != i) {
      struct probe_t tmp = pba->elements[offset + i];
      pba->elements[offset + i] = pba->elements[offset + j];
      pba->elements[offset + j] = tmp;
    }
  }
}

#ifndef NDEBUG
/* Returns whether pba is sorted by ${nanoes} */
static bool pba_is_sorted(struct pba_t* pba, int64_t offset, int64_t length) {
  for (int64_t i = 1; i < length; i++) {
    if (pba->elements[offset + i].nanoes < pba->elements[offset + i - 1].nanoes) {
      return false;
    }
  }
  return true;
}
#endif

#ifndef NDEBUG
/* Returns permutation-immune checksum */
static int64_t pba_checksum(struct pba_t* pba) {
  int64_t result = 0;
  for (int64_t i = 0; i < pba->length; i++) {
    result ^= pba->elements[i].offset;
    result ^= pba->elements[i].nanoes;
    result ^= pba->elements[i].base_offset;
  }
  return result;
}
#endif

/*
 * Anderson-Darling uniformity test applied to given region.
 * Region must be sorted.
 */
static double pba_adtest(struct pba_t* pba, int64_t offset, int64_t length) {
  assert(offset >= 0 && offset < pba->length);
  assert(length >= 0 && offset + length <= pba->length);
  assert(pba_is_sorted(pba, offset, length));

  double min_value = pba->elements[offset].nanoes;
  double max_value = pba->elements[offset+length-1].nanoes;

  // remove elements equal to ${min_value} or ${max_value}
  while (!(pba->elements[offset].nanoes > min_value) && length >= 0) {
    offset++;
    length--;
  }
  while (!(pba->elements[offset+length-1].nanoes < max_value) && length >= 0) {
    length--;
  }

  double s = 0.0;
  for (int64_t i = 1; i <= length; i++) {
    double value = pba->elements[offset+i-1].nanoes;
    value = (value - min_value) / (max_value - min_value);
    s += to_double(2*i-1)*log(value);
    s += to_double((2*length)+1-(2*i))*log(1.0 - value);
  }
  double a2 = -(to_double(length) + (s/to_double(length)));
  assert(a2 >= 0.0);
  return a2; 
}

/*
 * Bootstrapped version of AD test.
 * Makes ${passes} runs each with ${probes_per_pass} random probes and returns 
 * median value among all runs.
 * Region must be sorted.
 */
static double pba_adtest_bootstrap(struct pba_t* pba,
                                   int64_t offset, int64_t length,
                                   int64_t passes, int64_t probes_per_pass) {
  
  assert(offset >= 0 && offset < pba->length);
  assert(length >= 0 && offset + length <= pba->length);
  assert(pba_is_sorted(pba, offset, length));
  assert(probes_per_pass >= 0 && probes_per_pass <= length);
  
  double values[passes];
  for (int64_t i = 0; i < passes; i++) {
    pba_shuffle(pba, offset, length);
    pba_partial_qsort(pba, offset, probes_per_pass, probes_per_pass);
    double ad2 = pba_adtest(pba, offset, probes_per_pass);
    
    values[i] = ad2;
    for (int64_t j = i; j > 0; j--) {
      if (!(values[j-1] <= values[j])) {
        double tmp = values[j];
        values[j] = values[j-1];
        values[j-1] = tmp;
      }
    }
    
    if (debug) {
      report("iter #%"PRId64" -> %f\n", i, ad2);
    }
  }
  pba_partial_qsort(pba, offset, length, length);
  assert(pba_is_sorted(pba, offset, length));
  
  if (passes % 2 == 1) {
    return values[passes/2];
  } else {
    return (values[passes/2] + values[passes/2+1]) / 2.0;
  }
}

struct pba_stats_t {
  struct probe_t min_probe;   // probe with minimal ${nanoes}
  struct probe_t p90_probe;   // probe with ${nanoes} greater than 90% of probes
  struct probe_t p98_probe;   //
  struct probe_t max_probe;   //
  struct probe_t max_probes[8]; // up to ${length} slowest probes sorted descendently
  int64_t avg_nanoes;
  int64_t stddev_nanoes;
  int64_t glb_start_time;     // when first probe was made
  int64_t glb_finish_time;    // when last probe was completed
  int64_t length;             // number of probes
};

static void pba_statistics(struct pba_t* pba, struct pba_stats_t* stats) {
  stats->min_probe = (struct probe_t) {0, 0, 0};
  stats->p90_probe = (struct probe_t) {0, 0, 0};
  stats->p98_probe = (struct probe_t) {0, 0, 0};
  stats->max_probe = (struct probe_t) {0, 0, 0};
  stats->avg_nanoes = 0;
  stats->stddev_nanoes = 0;
  stats->glb_start_time = pba->glb_start_time;
  stats->glb_finish_time = pba->glb_finish_time;
  stats->length = pba->length;
  for (int i = 0; i < arrlen(stats->max_probes); i++) {
    stats->max_probes[i] = (struct probe_t) {0, 0, 0};
  }
  
  if (pba->length <= 0) {
    return;
  }
  
  /*
   *             length - floor(0.1*length)                  floor(0.1*length)
   * ####################################################v #####################
   *                  min, unsorted                    p90      max, sorted
   */
  int64_t limit90 = pba->length / 10;
  int64_t limit98 = pba->length / 50;
  int64_t limit = min(max(limit90 + 1, arrlen(stats->max_probes)), pba->length);
# ifndef NDEBUG
    int64_t checksum_before = pba_checksum(pba);
# endif
  pba_partial_qsort(pba, 0, pba->length, limit);
# ifndef NDEBUG
    int64_t checksum_after = pba_checksum(pba);
    assert(checksum_before == checksum_after);
# endif
  assert(pba_is_sorted(pba, pba->length - limit, limit));
  
  // this immediately gives us ${max_probe}, ${p90_probe} and ${p98_probe}
  stats->max_probe = pba->elements[pba->length - 1];
  stats->p90_probe = pba->elements[pba->length - 1 - limit90];
  stats->p98_probe = pba->elements[pba->length - 1 - limit98];
  
  // scan through array for ${min_probe} and ${avg_nanoes}
  double sum_nanoes = pba->elements[0].nanoes;
  stats->min_probe = pba->elements[0];
  for (int64_t i = 1; i < pba->length; i++) {
    sum_nanoes += pba->elements[i].nanoes;
    if (pba->elements[i].nanoes < stats->min_probe.nanoes) {
      stats->min_probe = pba->elements[i];
    }
  }
  stats->avg_nanoes = to_int64(sum_nanoes / pba->length);
  
  // scan once again to compute ${stddev_nanoes}
  double sum_sqdev_nanoes = 0.0;
  for (int64_t i = 0; i < pba->length; i++) {
    double dev = pba->elements[i].nanoes - stats->avg_nanoes;
    sum_sqdev_nanoes += dev * dev;
  }
  stats->stddev_nanoes = to_int64(sqrt(sum_sqdev_nanoes / pba->length));

  // max_probes
  for (int64_t i = 0; i < min(arrlen(stats->max_probes), pba->length); i++) {
    stats->max_probes[i] = pba->elements[pba->length-1-i];
  }
  
  // bunch of asserts
  assert(stats->min_probe.nanoes <= stats->avg_nanoes);
  assert(stats->avg_nanoes <= stats->max_probe.nanoes);
  
  assert(stats->min_probe.nanoes <= stats->p90_probe.nanoes);
  assert(stats->p90_probe.nanoes <= stats->p98_probe.nanoes);
  assert(stats->p98_probe.nanoes <= stats->max_probe.nanoes);
  
  assert(stats->stddev_nanoes <= (stats->max_probe.nanoes - stats->min_probe.nanoes));
}

/*
 * Computes median of probe array in given region.
 * Region must be sorted.
 */
static int64_t pba_median(struct pba_t* pba, int64_t offset, int64_t length) {
  assert(pba_is_sorted(pba, offset, length));

  if (length == 0) {
    return 0;
  } else if (length/2 == 1) {
    return pba->elements[offset+(length/2)].nanoes;
  } else {
    int64_t median = 0;
    median += pba->elements[offset+(length/2)].nanoes;
    median += pba->elements[offset+(length/2)+1].nanoes;
    median /= 2;
    return median;
  }
}

/* 
 * Computes Median Absolute Deviation (MAD) of given region.
 * Region must be sorted.
 */
static int64_t pba_mad(struct pba_t* pba, int64_t offset, int64_t length) {
  assert(pba_is_sorted(pba, offset, length));

  int64_t median = pba_median(pba, offset, length);

  // remove length/2 elements with largest deviations from left and right
  int64_t left = offset;
  int64_t right = offset+length-1;
  for (int64_t i = 0; i < length/2; i++) {
    int64_t left_dev = abs64(median - pba->elements[left].nanoes);
    int64_t right_dev = abs64(median - pba->elements[right].nanoes);
    if (left_dev >= right_dev) {
      left++;
    } else {
      right--;
    }
  }

  /* MAD is either left or right element */
  if (!(right >= left)) {
    return 0;
  } else {
    int64_t left_dev = abs64(median - pba->elements[left].nanoes);
    int64_t right_dev = abs64(median - pba->elements[right].nanoes);
    return max(left_dev, right_dev);
  }
}

static void pba_dump_field(struct tsv_t* tsv, struct probe_t* probe, const struct field_t* field) {
  switch (field->id) {
    case FLD_BASE_OFFSET:
      tsv_write_int64(tsv, probe->base_offset);
      break;
    case FLD_OFFSET:
      tsv_write_int64(tsv, probe->offset);
      break;
    case FLD_ABSDELTA:
      tsv_write_int64(tsv, abs64(probe->offset - probe->base_offset));
      break;
    case FLD_PROBE_LENGTH:
      tsv_write_int64(tsv, probe_length);
      break;
    case FLD_MILLIS:
      tsv_write_double(tsv, probe->nanoes / 1E6);
      break;
    default:
      die("Unknown field `%s'\n", field->name);
  }
}

/*
 * Dumps all probes from ${pba} into ${filename} in tab-separated-values format.
 * ${fields} controls which fields are written for each probe.
 */
static void pba_dump_all(struct pba_t* pba, const char* filename, const struct field_t** fields) {
  struct tsv_t tsv;
  tsv_open(&tsv, filename);
  
  // header
  for (int i = 0; fields[i] != NULL; i++) {
    tsv_write_string(&tsv, fields[i]->name);
  }
  tsv_newline(&tsv);
  
  // data
  for (int64_t i = 0; i < pba->length; i++) {
    for (int j = 0; fields[j] != NULL; j++) {
      pba_dump_field(&tsv, &pba->elements[i], fields[j]);
    }
    tsv_newline(&tsv);
  }
  
  tsv_close(&tsv);
}
 
static void pba_report_latencies(struct pba_stats_t* stats) {
  int fw = snprintf(NULL, 0, "%.3f", stats->max_probe.nanoes/1E6); // field width
  report("  min  %*.3f ms\n",                              fw, stats->min_probe.nanoes/1E6);
  report("  avg  %*.3f ms, stddev %.3f ms\n",              fw, stats->avg_nanoes/1E6, stats->stddev_nanoes/1E6);
  report("  p90  %*.3f ms (90%% of probes were faster)\n", fw, stats->p90_probe.nanoes/1E6);
  report("  p98  %*.3f ms\n",                              fw, stats->p98_probe.nanoes/1E6);
  report("  max  %*.3f ms (",                              fw, stats->max_probe.nanoes/1E6);
  for (int64_t i = 0; i < min(arrlen(stats->max_probes), stats->length); i++) {
    if (i > 0) {
      report(" ");
    }
    report("%*.3f", fw, stats->max_probes[i].nanoes/1E6);
  }
  report(")\n");
}

  
/***************************** IO BUFFER *******************************/

struct buffer_t {
  char* data;
  int64_t length;
};

/*
 * Initializes buffer to be used with IO operations:
 * - aligned by ${sc_page_size}
 * - size is limited, if probe length is greater than request is split into multiple requests
 * - filled with random data if operation is OP_WRITE
 */
static void buffer_init(struct buffer_t* buffer) {
  buffer->length = min(max_buffer_size, probe_length);
  if (buffer->length < probe_length) {
    warn("Using smaller buffer (--max-buffer-size=%"PRId64") than request is (%"PRId64")\n",
      buffer->length,
      probe_length
    );
  }
  buffer->data = dymalloca(buffer->length, sc_page_size);
  if (test->operation->id == OP_WRITE) {
    rnd_fill_random(buffer->data, buffer->length);
  }
}

static void buffer_deinit(struct buffer_t* buffer) {
  dyfree(buffer->data);
}


/**************************** SYSTEM FUNCTIONS ******************************/

/*
 * Ugly, but there is no better way...
 * 
 * ... And now compare this with number syscalls to flush buffers: sync(), syncfs(), fsync(),
 * fdatasync(), ioctl(BLKFLSBUF)) -- all imaginable levels of granularity!
 */
static void drop_caches() {
  const char* path = "/proc/sys/vm/drop_caches";
  const char value = '3';
  
  if (access(path, W_OK) != 0) {
    die("Can't drop page cache: no permissions\n");
  }
  
  int fd = open(path, O_WRONLY);
  if (fd == -1) {
    die("open(%s): %s\n", path, strerror(errno));
  }
  if (write(fd, &value, 1) != 1) {
    die("write(%s): %s\n", path, strerror(errno));
  }
  close(fd);
}

static void sync_buffers(int fd) {
  if (fsync(fd) == -1) {
    die("fsync(): %s\n", strerror(errno));
  }
}

static int64_t now_nanoes() {
  // strange, but CLOCK_MONOTONIC is ~3 times faster than CLOCK_MONOTONIC_RAW (x86_64)
  struct timespec tp;
  clock_gettime(CLOCK_MONOTONIC, &tp);
  return to_int64(tp.tv_sec)*1000*1000*1000 + to_int64(tp.tv_nsec);
}

/*
 * Performs given IO operation.
 * If buffer is smaller than ${length}, vector IO is used, possibly multiple times.
 */
static void perform_io(int fd, int64_t offset, int64_t length, const struct operation_t* op,
                       struct buffer_t* buffer) {
  
  int64_t position = offset;
  int64_t remaining = length;
  
  while (remaining > 0) {
    int64_t iovcnt = (remaining + buffer->length - 1) / buffer->length;
    iovcnt = min(iovcnt, sc_iov_max);

    struct iovec iov[iovcnt];
    for (int64_t i = 0, r = remaining; i < iovcnt; i++) {
      iov[i].iov_base = buffer->data;
      iov[i].iov_len = min(buffer->length, r);
      r -= iov[i].iov_len;
    }
    
    int64_t cnt;
    switch (op->id) {
      case OP_READ: {
        cnt = preadv(fd, iov, iovcnt, position);
        if (cnt == -1) {
          die("preadv(): %s\n", strerror(errno));
        } else if (cnt == 0) {
          die("preadv(): EOF\n");
        }
        break;
      }
      case OP_WRITE: {
        cnt = pwritev(fd, iov, iovcnt, position);
        if (cnt == -1) {
          die("pwritev(): %s\n", strerror(errno));
        }
        break;
      }
      default: {
        die("Invalid operation: `%s'\n", op->name);
      }
    }
    
    position += cnt;
    remaining -= cnt;
  }
}

/****************************** CONTEXT VARIABLES **********************************/
 
static struct bdev_t* bdev = NULL;
static int file_fd = -1;
static int64_t file_length = 0;
 
static void dump_context_vars() {
  report("Context vars:\n");
  report("  bdev ...............  %s\n",        deref2(bdev, name));
  report("  file length ........  %"PRId64"\n", file_length);
  report("\n");
}


/***************************** OFFSET GENERATORS ******************************/

inline static void check_offset_in_window(int64_t offset, int64_t wbegin, int64_t wend) {
  if (offset < wbegin || offset >= wend) {
    die("Offset %"PRId64" is not in range [%"PRId64",%"PRId64"]. File too small?\n", offset, wbegin, wend);
  }
}

inline static void check_offset_is_aligned(int64_t offset) {
  if (offset != (offset / offset_alignment * offset_alignment)) {
    die("Offset %"PRId64" is not aligned by %"PRId64"\n", offset, offset_alignment);
  }
}

inline static void check_offset(int64_t offset, int64_t wbegin, int64_t wend) {
  check_offset_in_window(offset, wbegin, wend);
  check_offset_in_window(offset + probe_length - 1, wbegin, wend);
  check_offset_is_aligned(offset);
}
 

/*
 * Returns ${i}-th by order offset among possible [0..${probe_count}) offsets which split window space evenly.
 * Returned offset lies in [${window_begin}, ${window_end}-${probe_length}) and is aligned by ${offset_alignment}.
 * Caller MUST be sure that at least single offset exists satysfying above conditions.
 */
static int64_t make_sequential_offset(int64_t i) {
  assert(i >= 0 && i < probe_count);
  
  int64_t first_valid_index = (window_begin + probe_length - 1) / offset_alignment;
  int64_t last_valid_index = (window_end - probe_length) / offset_alignment;
  
  int64_t index;
  if (probe_count > 1) {
    int64_t index_count = last_valid_index - first_valid_index + 1;
    int64_t index_offset = to_int64((index_count - 1) / (probe_count - 1) * i);
    index = first_valid_index + index_offset;
  } else {
    index = first_valid_index + ((last_valid_index - first_valid_index) / 2);
  }
  int64_t r = index * offset_alignment;
  
  check_offset(r, window_begin, window_end);
  return r;
}

/*
 * Returns random offset which is in range [${wbegin}, ${wend}-${probe_length}) and is aligned by ${offset_alignment}.
 * Caller must guarantee that at least one offset exists satifsying above conditions.
 */
static int64_t make_random_offset(int64_t wbegin, int64_t wend) {
  int64_t first_valid_index = (wbegin + probe_length - 1) / offset_alignment;
  int64_t last_valid_index = (wend - probe_length) / offset_alignment;
  
  int64_t r = rnd_u64_range(first_valid_index, last_valid_index) * offset_alignment;
  
  check_offset(r, wbegin, wend);
  return r;
}

struct offset_pair_t {
  int64_t src;
  int64_t dst;
};

/*
 * Returns pair of offsets with random delta between them. Both of offsets lie in 
 * [${window_begin}, ${window_end}-${probe_length}) and are aligned by ${offset_alignment}. 
 * Caller MUST be sure that at least single offset exists satysfying above conditions.
 */
static struct offset_pair_t make_random_delta_offset_pair() {
  int64_t first_valid_index = (window_begin + probe_length - 1) / offset_alignment;
  int64_t last_valid_index = (window_end - probe_length) / offset_alignment;
  
  int64_t index_delta = rnd_u64_range(0, last_valid_index - first_valid_index);
  int64_t src_index = rnd_u64_range(first_valid_index, last_valid_index - index_delta);
  
  struct offset_pair_t r;
  r.src = src_index * offset_alignment;
  r.dst = (src_index + index_delta) * offset_alignment;
  
  if (rnd_u64_range(0, 1)) {
    int64_t tmp = r.src;
    r.src = r.dst;
    r.dst = tmp;
  }
  
  check_offset(r.src, window_begin, window_end);
  check_offset(r.dst, window_begin, window_end);
  return r;
}


/************************* SEQUENTIAL ACCESS TEST *************************/

static void seq_print_header() {
  report("    pct  |               offset |      time |        speed \n");
}

static void seq_print_delim() {
  report("-----------------------------------------------------------\n");
}

static void seq_print_progress(int64_t i, struct long_probe_t* probe) {
  int64_t elapsed = probe->finish_time - probe->start_time;
  report(" %6.2f%% | %'20"PRId64" | %6"PRId64" ms | %7.2f MB/s\n",
    (i + 1) * 100.0 / probe_count,
    to_int64(probe->offset),
    to_int64(elapsed / 1E6),
    (probe_length / 1E6) / (elapsed / 1E9)
  );
}

static void seq_print_results(struct pba_stats_t* stats) {
  report("Sequential %s, each probe %'"PRId64" bytes long:\n", test->operation->name, probe_length);
  report("  min speed %.2f MB/sec (at offset %'"PRId64")\n",
    (probe_length / 1E6) / (stats->max_probe.nanoes / 1E9),
    to_int64(stats->max_probe.offset)
  );
  report("  avg speed %.2f MB/sec\n", (probe_length / 1E6) / (stats->avg_nanoes / 1E9));
  report("  max speed %.2f MB/sec (at offset %'"PRId64")\n",
    (probe_length / 1E6) / (stats->min_probe.nanoes / 1E9),
    to_int64(stats->min_probe.offset)
  );
}

static void seq_run_sequential_test() {
  struct pba_t pba;
  pba_init(&pba, probe_count);
  
  struct buffer_t buffer;
  buffer_init(&buffer);
  
  seq_print_header();
  seq_print_delim();
  
  for (int64_t i = 0; i < probe_count; i++) {
    int64_t offset = make_sequential_offset(i);
    
    int64_t start_time = now_nanoes();
    perform_io(file_fd, offset, probe_length, test->operation, &buffer);
    int64_t finish_time = now_nanoes();
    
    struct long_probe_t probe = {
      .offset = offset,
      .start_time = start_time,
      .finish_time = finish_time
    };
    pba_add(&pba, &probe);
    seq_print_progress(i, &probe);
  }
  seq_print_delim();

  if (dump_file) {
    pba_dump_all(&pba, dump_file, test->fields);
  }

  struct pba_stats_t stats;
  pba_statistics(&pba, &stats);
  seq_print_results(&stats);

  pba_deinit(&pba);
  buffer_deinit(&buffer);
}


/************************ WORKFLOWS *****************************/

struct collector_t {
  void (*collect)(void* self, struct long_probe_t* probe);
};

typedef void (*rnd_workflow_fn)(int64_t concurrent, struct collector_t* collector);

static void kaio_workflow(int64_t concurrent, struct collector_t* collector);
static void bio_workflow(int64_t concurrent, struct collector_t* collector);

static rnd_workflow_fn get_workflow_function(const struct method_t* method, int64_t concurrent) {
  switch (method->id) {
    case M_BIO:
      return &bio_workflow;
    case M_KAIO:
      return &kaio_workflow;
    case M_AUTO:
    default:
      if (concurrent == 1) {
        return &bio_workflow;
      } else {
        return &kaio_workflow;
      }
  }
  die("Unsupported method %s\n", method->name);
}


/********************** KERNEL AIO WORKFLOW **************************/

struct kaio_request_t {
  struct iocb cb;
  struct buffer_t buf;
  int64_t start_time;
  int64_t finish_time;
  int64_t _errno;
};

/*
 * Lifetime of logical request:
 * - kaio_enqueue_next_request(): creates new request and adds it into ${iocbs} queue
 * - kaio_submit_enqueued_requests(): submits all requests from ${iocbs} queue to kernel and empties ${iocbs}
 * - kaio_ensure_has_completed_requests(): request is completed and its completion event is added into ${events} queue
 * - kaio_dequeue_completed_request(): removes single completed request from ${events} queue
 */
struct kaio_context_t {
  aio_context_t ctx;
  int64_t concurrent;
  
  /*
   * Pool of reusable request objects.
   */ 
  struct kaio_request_t* requests;
  
  /*
   * Pointers into ${requests} which are not currently in use.
   */
  struct kaio_request_t** unused_requests;
  int64_t unused_requests_length;
  
  /*
   * Queue of requests to submit.
   * ${iocb.aio_data} is index into ${requests} array.
   */
  struct iocb** iocbs;
  int64_t iocb_length;
  
  /*
   * Queue of completed events.
   * ${io_event.data} is index into ${requests} array.
   */
  struct io_event* events;
  int64_t events_length;
};

static void kaio_init(struct kaio_context_t* ctx, int64_t concurrent) {
  // requests
  ctx->requests = dymalloc(concurrent * sizeof(struct kaio_request_t));
  for (int64_t i = 0; i < concurrent; i++) {
    memset(&ctx->requests[i].cb, 0, sizeof(struct iocb));
  }
  for (int64_t i = 0; i < concurrent; i++) {
    buffer_init(&ctx->requests[i].buf);
    
    ctx->requests[i].cb.aio_fildes = file_fd;
    ctx->requests[i].cb.aio_buf = to_uint64(ctx->requests[i].buf.data);
    ctx->requests[i].cb.aio_nbytes = probe_length;
    ctx->requests[i].cb.aio_lio_opcode = test->operation->iocb_opcode;
    ctx->requests[i].cb.aio_data = i;
  }
  
  // unused requests
  ctx->unused_requests = dymalloc(concurrent * sizeof(struct kaio_request_t*));
  for (int64_t i = 0; i < concurrent; i++) {
    ctx->unused_requests[i] = &ctx->requests[i];
  }
  ctx->unused_requests_length = concurrent;
  
  // events
  ctx->events = dymalloc(concurrent * sizeof(struct io_event));
  ctx->events_length = 0;
  
  // iocbs
  ctx->iocbs = dymalloc(concurrent * sizeof(struct iocb*));
  ctx->iocb_length = 0;
 
  // aio ctx
  ctx->ctx = 0;
  ctx->concurrent = concurrent;
  if (io_setup(concurrent, &ctx->ctx) != 0) {
    die("io_setup(): %s\n", strerror(errno));
  }
}

static void kaio_deinit(struct kaio_context_t* ctx) {
  io_destroy(ctx->ctx);
  dyfree(ctx->events);
  dyfree(ctx->iocbs);
  if (ctx->requests) {
    for (int64_t i = 0; i < ctx->concurrent; i++) {
      buffer_deinit(&ctx->requests[i].buf);
    }
    dyfree(ctx->requests);
  }
  dyfree(ctx->unused_requests);
}

/*
 * Moves all enqueued requests into kernel.
 */
static void kaio_submit_enqueued_requests(struct kaio_context_t* ctx) {
  if (ctx->iocb_length > 0) {
    int64_t now = now_nanoes();
    for (int64_t i = 0; i < ctx->iocb_length; i++) {
      ctx->requests[ctx->iocbs[i]->aio_data].start_time = now;
    }
    if (io_submit(ctx->ctx, ctx->iocb_length, ctx->iocbs) != ctx->iocb_length) {
      die("io_submit(): %s\n", strerror(errno));
    }
    ctx->iocb_length = 0;
  }
}

/*
 * Moves completed requests from kernel into events.
 */
static void kaio_ensure_has_completed_requests(struct kaio_context_t* ctx) {
  while (ctx->events_length == 0) {
    struct timespec timeout = {
      .tv_sec = 0,
      .tv_nsec = 1000*1000
    };
    int cnt = io_getevents(ctx->ctx, 1, ctx->concurrent, ctx->events, &timeout);
    int64_t now = now_nanoes(); // log IO completion as soon as possible
    if (cnt < 0) {
      if (errno != EINTR) {
        die("io_getevents(): %s\n", strerror(errno));
      }
      cnt = 0;
    }
    for (int i = 0; i < cnt; i++) {
      struct io_event* event = &ctx->events[i];
      struct kaio_request_t* request = &ctx->requests[event->data];
      request->finish_time = now;
      request->_errno = -event->res;
    }
    ctx->events_length += cnt;
  }
}

static struct kaio_request_t* kaio_acquire_unused_request(struct kaio_context_t* ctx) {
  assert(ctx->unused_requests_length > 0);
  return ctx->unused_requests[--ctx->unused_requests_length];
}

static void kaio_release_unused_request(struct kaio_context_t* ctx, struct kaio_request_t* req) {
  assert(ctx->unused_requests_length < ctx->concurrent);
  ctx->unused_requests[ctx->unused_requests_length++] = req;
}

inline static bool kaio_has_unused_requests(struct kaio_context_t* ctx) {
  return ctx->unused_requests_length > 0;
}

inline static bool kaio_has_completed_requests(struct kaio_context_t* ctx) {
  return ctx->events_length > 0;
}

static struct kaio_request_t* kaio_dequeue_completed_request(struct kaio_context_t* ctx) {
  assert(ctx->events_length > 0);
  
  struct io_event* event = &ctx->events[--ctx->events_length];
  struct kaio_request_t* req = &ctx->requests[event->data];
  
  return req;
}

static void kaio_check_request_status(struct kaio_request_t* req) {
  if (req->_errno > 0) {
    die("%s error: %s\n", test->operation->name, strerror(req->_errno));
  }
}

static void kaio_prepare_request(struct kaio_request_t* req, int64_t offset) {
  req->cb.aio_offset = offset;
}

static void kaio_enqueue_request(struct kaio_context_t* ctx, struct kaio_request_t* req) {
  assert(ctx->iocb_length < ctx->concurrent);
  ctx->iocbs[ctx->iocb_length++] = &req->cb;
}

static void kaio_workflow(int64_t concurrent, struct collector_t* collector) {
  if (cache_policy->id != CP_BYPASS) {
    warn("--method kaio works truly concurrently only with O_DIRECT (--cache bypass)\n");
  }

  struct kaio_context_t ctx;
  kaio_init(&ctx, concurrent);
  
  int64_t unsubmitted_probes = probe_count;
  int64_t inprogress_probes = 0;
  int64_t completed_probes = 0;
  
  // initial load
  while (unsubmitted_probes > 0 && kaio_has_unused_requests(&ctx)) {
    struct kaio_request_t* req = kaio_acquire_unused_request(&ctx);
    kaio_prepare_request(req, make_random_offset(window_begin, window_end));
    kaio_enqueue_request(&ctx, req);
    unsubmitted_probes--;
    inprogress_probes++;
  }
  kaio_submit_enqueued_requests(&ctx);
  
  // main loop
  while (unsubmitted_probes > 0 || inprogress_probes > 0) {
    kaio_ensure_has_completed_requests(&ctx);
    
    while (kaio_has_completed_requests(&ctx)) {
      // get next completed request
      struct kaio_request_t* req = kaio_dequeue_completed_request(&ctx);
      inprogress_probes--;
      completed_probes++;
      kaio_check_request_status(req);
      
      // register probe
      struct long_probe_t probe = {
        .offset = req->cb.aio_offset,
        .start_time = req->start_time,
        .finish_time = req->finish_time
      };
      collector->collect(collector, &probe);
      
      // use it as free slot to create new request
      if (unsubmitted_probes > 0) {
        kaio_prepare_request(req, make_random_offset(window_begin, window_end));
        kaio_enqueue_request(&ctx, req);
        unsubmitted_probes--;
        inprogress_probes++;
      } else {
        kaio_release_unused_request(&ctx, req);
      }
    }

    kaio_submit_enqueued_requests(&ctx);
  }

  assert(unsubmitted_probes == 0);
  assert(inprogress_probes == 0);
  assert(completed_probes == probe_count);

  kaio_deinit(&ctx);
}


/********************************* BLOCKING IO WORKFLOW ******************************************/

/*
 * Standard blocking IO using read()/write().
 */
static void bio_workflow(int64_t concurrent, struct collector_t* collector) {
  if (concurrent != 1) {
    die("Blocking IO is not able to make probes concurrently (%"PRId64")\n", concurrent);
  }
  
  struct buffer_t buffer;
  buffer_init(&buffer);
  
  for (int64_t i = 0; i < probe_count; i++) {
    int64_t offset = make_random_offset(window_begin, window_end);
    
    int64_t start_time = now_nanoes();
    perform_io(file_fd, offset, probe_length, test->operation, &buffer);
    int64_t finish_time = now_nanoes();

    struct long_probe_t probe = {
      .offset = offset,
      .start_time = start_time,
      .finish_time = finish_time
    };
    collector->collect(collector, &probe);
  }
  
  buffer_deinit(&buffer);
}


/********************************* RANDOM ACCESS TEST ******************************************/

static void rnd_print_header() {
  report("     pct |           ops |      time |            speed \n");
}

static void rnd_print_delim() {
  report("--------------------------------------------------------\n");
}

static void rnd_print_progress(int64_t probes_total, int64_t probes_period, int64_t nanoes_period) {
  report(" %6.2f%% | %13"PRId64" | %6.0f ms | %11.0f IOPS\n",
    probes_total * 100.0 / probe_count,
    probes_period,
    nanoes_period / 1E6,
    probes_period / (nanoes_period / 1E9)
  );
}

static void rnd_print_results(struct pba_stats_t* stats) {
  // description
  report("Random %s", test->operation->name);
  report(", each probe %"PRId64" bytes", probe_length);
  if (offset_alignment > 1) {
    report(", alignment %"PRId64, offset_alignment);
  } else {
    report(", nonaligned");
  }
  if (concurrent > 1) {
    report(", max %"PRId64" concurrent requests", concurrent);
  }
  report("\n");
  
  // latency
  report("Latency:\n");
  pba_report_latencies(stats);
  
  // throughput
  double iops = probe_count / ((stats->glb_finish_time - stats->glb_start_time) / 1E9);
  int tfw = snprintf(NULL, 0, "%.0f", iops);
  report("Throughput:\n");
  report("  overall             %*.0f IOPS\n", tfw, iops);
  report("  overall/concurrent  %*.0f IOPS\n", tfw, iops / concurrent);
}

struct rnd_context_t {
  struct collector_t collector;
  struct pba_t pba;
  int64_t total_probes;
  int64_t completed_probes;
  int64_t probes_since_progress;
  int64_t last_progress_time;
};

static void rnd_collect(void* self, struct long_probe_t* probe) {
  struct rnd_context_t* ctx = get_base_pointer(self, struct rnd_context_t, collector);
  
  pba_add(&ctx->pba, probe);
  
  ctx->probes_since_progress++;
  ctx->completed_probes++;
  
  /*
   * Double check to reduce excessive number of calls to now_nanoes().
   */
  if (is_power2(ctx->probes_since_progress) || (ctx->completed_probes == ctx->total_probes)) {
    int64_t now = now_nanoes();
    if ((now - ctx->last_progress_time) >= 1E9 || (ctx->completed_probes == ctx->total_probes)) {
      rnd_print_progress(ctx->completed_probes, ctx->probes_since_progress, now - ctx->last_progress_time);
      ctx->last_progress_time = now;
      ctx->probes_since_progress = 0;
      ctx->last_progress_time = now_nanoes();
    }
  }
}

static void rnd_run_random_test() {
  struct rnd_context_t ctx = {
    .collector = {
      .collect = &rnd_collect
    },
    .total_probes = probe_count,
    .completed_probes = 0,
    .probes_since_progress = 0,
    .last_progress_time = now_nanoes()
  };
  pba_init(&ctx.pba, probe_count);

  rnd_print_header();
  rnd_print_delim();
  get_workflow_function(method, concurrent)(concurrent, &ctx.collector);
  rnd_print_delim();
  
  if (dump_file) {
    pba_dump_all(&ctx.pba, dump_file, test->fields);
  }

  struct pba_stats_t stats;
  pba_statistics(&ctx.pba, &stats);
  rnd_print_results(&stats);
  
  pba_deinit(&ctx.pba);
}


/**************************** CONCURRENCY TEST ******************************/

struct cnc_result_t {
  int64_t concurrent;
  struct pba_stats_t stats;
};

static inline double cnc_get_tpt(struct cnc_result_t* res) {
  return res->stats.length / ((res->stats.glb_finish_time - res->stats.glb_start_time) / 1E9);
}

static inline double cnc_get_ilat(struct cnc_result_t* res) {
  return 1E6/res->stats.p90_probe.nanoes;
}

/*
 * Returns index of element from ${res} with best metric:
 *
 *                  1.0
 * -------------------------------------------
 *       0.8                   0.2
 * ----------------  +  ----------------------
 * norm(throughput)     norm(inv(p90_latency))
 */
static int64_t cnc_find_best_res(struct cnc_result_t* res, int64_t count) {
  assert(count > 0);

  double max_tpt = 0.0;
  double max_ilat = 0.0;
  for (int64_t i = 0; i < count; i++) {
    max_tpt = max(max_tpt, cnc_get_tpt(&res[i]));
    max_ilat = max(max_ilat, cnc_get_ilat(&res[i]));
  }
    
  int64_t best_i = 0;
  double best_rank = 0.0;
  for (int64_t i = 0; i < count; i++) {
    double norm_tpt = cnc_get_tpt(&res[i]) / max_tpt;
    double norm_ilat = cnc_get_ilat(&res[i]) / max_ilat;
    const double tpt_coef = 0.8;
    double rank = (norm_tpt * norm_ilat) / ((norm_tpt*(1.0-tpt_coef)) + (norm_ilat*tpt_coef));
    if (rank > best_rank) {
      best_rank = rank;
      best_i = i;
    }
    if (debug) {
      printf("i=%"PRId64" tpt=%f ilat=%f rank=%f\n", i, norm_tpt, norm_ilat, rank);
    }
  }
  return best_i;
}
 
static void cnc_print_header() {
  report(" cnc |     throughput | throughput/cnc | p90 latency\n");
}

static void cnc_print_delim() {
  report("-----------------------------------------------------\n");
}

static void cnc_print_progress(struct cnc_result_t* res) {
  report(" %3"PRId64" | %9.f IOPS | %9.f IOPS | %8.3f ms\n",
    res->concurrent,
    cnc_get_tpt(res),
    cnc_get_tpt(res) / res->concurrent,
    res->stats.p90_probe.nanoes/1E6
  );
}

static void cnc_print_results(struct cnc_result_t* opt, struct cnc_result_t* one) {
  report("Concurrency %s test:\n", test->operation->name);
  report("  optimal concurrency  %"PRId64"\n", opt->concurrent);

  report("Latency (at --concurrent=%"PRId64"):\n", opt->concurrent);
  pba_report_latencies(&opt->stats);

  report("Throughput (at --concurrent=%"PRId64"):\n", opt->concurrent);
  report("  total    %.0f IOPS\n", cnc_get_tpt(opt));
  report("  speedup  %.1f\n",      cnc_get_tpt(opt)/cnc_get_tpt(one));
}

struct cnc_ctx_t {
  struct collector_t collector;
  struct pba_t pba;
};

static void cnc_collect(void* self, struct long_probe_t* probe) {
  struct cnc_ctx_t* ctx = get_base_pointer(self, struct cnc_ctx_t, collector);
  pba_add(&ctx->pba, probe);
}

static void cnc_run_concurrency_test() {
  struct cnc_ctx_t ctx = {
    .collector = {
      .collect = &cnc_collect,
    }
  };
  pba_init(&ctx.pba, probe_count);
    
  cnc_print_header();
  cnc_print_delim();
  
  struct cnc_result_t results[256];
  int64_t best_i;
  for (int64_t i = 0; i < arrlen(results); i++) {
    int64_t cnc = i + 1;
    pba_clear(&ctx.pba);
    kaio_workflow(cnc, &ctx.collector);

    results[i].concurrent = cnc;
    pba_statistics(&ctx.pba, &results[i].stats);
    
    cnc_print_progress(&results[i]);
    
    best_i = cnc_find_best_res(results, i + 1);
    if (i >= (best_i + 10)) {
      break;
    }
  }
  cnc_print_delim();
  cnc_print_results(&results[best_i], &results[0]);
  
  pba_deinit(&ctx.pba);
}


/********************************* RANDOM DELTA TEST ******************************************/

static void rd_run_random_delta_test() {
  struct buffer_t buffer;
  buffer_init(&buffer);
  
  struct pba_t pba;
  pba_init(&pba, probe_count);
  
  for (int64_t i = 0; i < probe_count; i++) {
    struct offset_pair_t offpair = make_random_delta_offset_pair();
    
    perform_io(file_fd, offpair.src, probe_length, test->operation, &buffer);
    
    int64_t start_time = now_nanoes();
    perform_io(file_fd, offpair.dst, probe_length, test->operation, &buffer);
    int64_t finish_time = now_nanoes();
    
    struct long_probe_t probe = {
      .base_offset = offpair.src,
      .offset = offpair.dst,
      .start_time = start_time,
      .finish_time = finish_time
    };
    pba_add(&pba, &probe);
  }
  
  if (dump_file) {
    pba_dump_all(&pba, dump_file, test->fields);
  }
  
  buffer_deinit(&buffer);
  pba_deinit(&pba);
}


/********************************* HDD MECHANICS TESTS ****************************************/

struct hm_results_t {
  bool is_uniform;      // whether distribution is uniform
  int64_t low_nanoes;   // lowest non-outlier value
  int64_t high_nanoes;  // highest non-outlier value
};

/*
 * Analyzes and extracts useful info from probe array into ${results} struct.
 * Values which are more than 2 MADs apart from median are considered outliers and are removed.
 * Then checks are performed:
 *  - that number of removed outliers is reasonable
 *  - that values in remaining region are uniformly distributed
 */
static void hm_analyze(struct pba_t* pba, struct hm_results_t* results) {
  pba_partial_qsort(pba, 0, pba->length, pba->length);

  int64_t median_nanoes = pba_median(pba, 0, pba->length);
  int64_t mad_nanoes = pba_mad(pba, 0, pba->length);

  // search for indices of lowest and highest elements fitting into distribution
  // oovvvvvvvvvvvvvvvvvvvvvvvvvvvvoooo
  //   |                          |
  int64_t low = 0;
  int64_t high = pba->length-1;
  while (abs64(pba->elements[low].nanoes - median_nanoes) > mad_nanoes*2) {
    low++;
  }
  while (abs64(pba->elements[high].nanoes - median_nanoes) > mad_nanoes*2) {
    high--;
  }

  int64_t low_outliers = low;
  int64_t high_outliers = pba->length - high - 1;
  int64_t length = high - low + 1;

  double ad2 = pba_adtest_bootstrap(pba, low, length, 9, min(250, length));
  
  results->low_nanoes = pba->elements[low].nanoes;
  results->high_nanoes = pba->elements[high].nanoes;
  results->is_uniform = 
    (ad2 <= 6.0) &&
    (low_outliers <= pba->length/10) &&
    (high_outliers <= pba->length/10);

  if (debug) {
    report("median=%f ms\n", median_nanoes/1E6);
    report("mad=%f ms\n", mad_nanoes/1E6);
    report("outliers: low=%"PRId64" high=%"PRId64"\n", low_outliers, high_outliers);
  }
}

static void hm_print_header() {
  report("     pct |   probes \n");
}

static void hm_print_delim() {
  report("--------------------\n");
}

static void hm_print_progress(int64_t probes_done, int64_t probes_total) {
  report(" %6.2f%% | %8"PRId64"\n",
    probes_done * 100.0 / probes_total,
    probes_done
  );
}

static void hm_verify_rpm(double rpm) {
  static const double min_value = 1000.0;
  static const double max_value = 25000.0;

  if (!(rpm >= min_value && rpm <= max_value)) {
    warn("RPM is out of reasonable range [%f .. %f]\n", min_value, max_value);
  }
}

static void hm_verify_fullstroke(double fullstroke_millis) {
  static const double min_value = 5.0;
  static const double max_value = 50.0;
  
  if (!(fullstroke_millis >= min_value && fullstroke_millis <= max_value)) {
    warn("Fullstroke seek time is out of reasonable range [%fms .. %fms]\n", min_value, max_value);
  }
}

static void hm_verify_tracktotrack(double tracktotrack_millis) {
  static const double min_value = 0.5;
  static const double max_value = 5.0;
  
  if (!(tracktotrack_millis >= min_value && tracktotrack_millis <= max_value)) {
    warn("Track-to-track seek time is out of reasonable range [%fms .. %fms]\n", min_value, max_value);
  }
}

static void hm_verify_distribution(struct hm_results_t* results) {
  if (!results->is_uniform) {
    warn("Timing distribution is unexpected."
         " Check that device is raw HDD without high load and rerun test (possibly with larger --probes)\n");
  }
}

static void hm_verify_target() {
  if (bdev->pt_parent || bdev->md_slaves.length > 0) {
    warn("Path is not a physical device. Results may be incorrect.\n");
  }
  if (window_begin != 0 || window_end != file_length) {
    warn("Window doesn't cover whole device address space. Results may be incorrect.\n");
  }
}

static void hm_print_fullstroke_results(struct hm_results_t* results) {
  hm_verify_distribution(results);

  double fullstroke_millis = results->low_nanoes / 1E6;
  fullstroke_millis = fullstroke_millis / 0.98; // compensate 1% windows
  hm_verify_fullstroke(fullstroke_millis);

  double revolution_millis = (results->high_nanoes/1E6) - fullstroke_millis;
  double rpm = 60000 / revolution_millis;
  hm_verify_rpm(rpm);

  report("Fullstroke test results:\n");
  report("  fullstroke seek time  %.3f ms\n", fullstroke_millis);
  report("       revolution time  %.3f ms\n", revolution_millis);
  report("      rotational speed  %"PRId64" RPM\n", to_int64(rpm));
}

static void hm_print_tracktotrack_results(struct hm_results_t* results, int64_t maxcylsize) {
  hm_verify_distribution(results);
  
  double tracktotrack_millis = results->low_nanoes / 1E6;
  hm_verify_tracktotrack(tracktotrack_millis);

  double revolution_millis = (results->high_nanoes/1E6) - tracktotrack_millis;
  double rpm = 60000 / revolution_millis;
  hm_verify_rpm(rpm);

  report("Tracktotrack test results (with --maxcylsize=%"PRId64" bytes):\n", maxcylsize);
  report("  tracktotrack seek time: %.3f ms\n", tracktotrack_millis);
  report("         revolution time: %.3f ms\n", revolution_millis);
  report("        rotational speed: %"PRId64" RPM\n", to_int64(rpm));
}


/*
 * Measures fullstroke seek time and rotational latency.
 * 
 * Test is performed by making lots of jumps between low 1% of address space 
 * to high 1% and vice versa.
 * After removing outliers, fastest jump time equals to fullstroke seek time.
 * It corresponds to lucky situation when required sector was located exactly 
 * beneath the magnetic head after jump.
 * Conversely, slowest jump time equals to fullstroke time plus full rotation time.
 */
static void hm_run_fullstroke_test() {
  hm_verify_target();

  struct buffer_t buffer;
  buffer_init(&buffer);
  
  struct pba_t pba;
  pba_init(&pba, probe_count);
 
  // 1% of address space begin
  int64_t win_outer_begin = window_begin;
  int64_t win_outer_end = window_begin + ((window_end - window_begin) / 100);
  
  // 1% of address space end
  int64_t win_inner_begin = window_end - ((window_end - window_begin) / 100);
  int64_t win_inner_end = window_end;
  
  enum pos_id {
    POS_OUTER,
    POS_INNER
  };
  
  int64_t last_offset = 0;
  enum pos_id last_pos = POS_OUTER;
  
  int64_t cur_offset;
  enum pos_id cur_pos;
  
  int64_t print_ts = 0;
  
  hm_print_header();
  hm_print_delim();
  for (int64_t i = 0; i <= probe_count; i++) {
    if (last_pos == POS_OUTER) {
      cur_pos = POS_INNER;
      cur_offset = make_random_offset(win_inner_begin, win_inner_end);
    } else {
      cur_pos = POS_OUTER;
      cur_offset = make_random_offset(win_outer_begin, win_outer_end);
    }
    
    int64_t start_time = now_nanoes();
    perform_io(file_fd, cur_offset, probe_length, test->operation, &buffer);
    int64_t finish_time = now_nanoes();
    
    // first probe is initial positioning
    if (i > 0) {
      struct long_probe_t probe = {
        .base_offset = last_offset,
        .offset = cur_offset,
        .start_time = start_time,
        .finish_time = finish_time 
      };
      pba_add(&pba, &probe);
    }
    
    int64_t now_ts = now_nanoes();
    if ((now_ts - print_ts) >= 1000*1000*1000) {
      hm_print_progress(i, probe_count);
      print_ts = now_ts;
    }
    
    last_offset = cur_offset;
    last_pos = cur_pos;
  }
  hm_print_progress(probe_count, probe_count);
  hm_print_delim();
  
  // dump now because ${hm_analyze} will sort array
  if (dump_file) {
    pba_dump_all(&pba, dump_file, test->fields);
  }
  
  struct hm_results_t results;
  hm_analyze(&pba, &results);
  hm_print_fullstroke_results(&results);
  
  buffer_deinit(&buffer);
  pba_deinit(&pba);
}

/*
 * Performs single run of track-to-track test.
 * Makes ${probe_count} jumps, where each jump is in range [maxcylsize, 2*maxcylsize].
 */ 
static void hm_run_tracktotrack_once(struct pba_t* pba, struct buffer_t* buffer, 
                                     int64_t maxcylsize, int64_t probe_count) {

  // make maxcylsize multiple of probe_length, round up
  maxcylsize = (maxcylsize + (probe_length - 1)) * probe_length / probe_length;

  hm_print_header();
  hm_print_delim();
  int64_t print_ts = 0;
  for (int64_t i = 0; i < probe_count; i++) {
    int64_t base_offset = make_random_offset(window_begin, window_end - (2*maxcylsize));
    int64_t offset = make_random_offset(base_offset + (1*maxcylsize), base_offset + (2*maxcylsize));
    
    perform_io(file_fd, base_offset, probe_length, test->operation, buffer);
    
    int64_t start_time = now_nanoes();
    perform_io(file_fd, offset, probe_length, test->operation, buffer);
    int64_t finish_time = now_nanoes();
    
    struct long_probe_t probe = {
      .base_offset = base_offset,
      .offset = offset,
      .start_time = start_time,
      .finish_time = finish_time
    };
    pba_add(pba, &probe);
    
    int64_t now_ts = now_nanoes();
    if ((now_ts - print_ts) >= 1000*1000*1000) {
      hm_print_progress(i, probe_count);
      print_ts = now_ts;
    }
  }
  hm_print_progress(probe_count, probe_count);
  hm_print_delim();
}

inline static int64_t hm_pow(int64_t power) {
  return (to_int64(1) << power) * probe_length;
}

static void hm_run_tracktotrack_test() {
  hm_verify_target();

  struct buffer_t buffer;
  buffer_init(&buffer);
  
  struct pba_t pba;
  pba_init(&pba, probe_count);
  
  struct hm_results_t results;

  if (maxcylsize != -1) {
    hm_run_tracktotrack_once(&pba, &buffer, maxcylsize, probe_count);
    hm_analyze(&pba, &results);
    hm_print_tracktotrack_results(&results, maxcylsize);

  } else {
    // range of valid ${maxcylsize}: (2^min_power)*probe_length .. (2^max_power)*probe_length
    const int64_t min_power = 7;  //    128 * probe_length
    const int64_t max_power = 17; // 131072 * probe_length

    int64_t power = -1;

    // binary search ${maxcylsize} with reduced number of samples
    int64_t low = min_power;
    int64_t high = max_power;
    while (low <= high) {
      int64_t mid = (low + high) / 2;
      
      report("\n");
      report("Searching for --maxcylsize value, trying %"PRId64" bytes\n", hm_pow(mid));
      pba_clear(&pba);
      hm_run_tracktotrack_once(&pba, &buffer, hm_pow(mid), probe_count/5);
      hm_analyze(&pba, &results);
      
      if (results.is_uniform) {
        high = mid - 1;
        power = mid;
      } else {
        low = mid + 1;
      }
    }

    // iterative scan with full probe_count
    if (power != -1) {
      for (; power <= max_power; power++) {
        report("\n");
        report("Using --maxcylsize of %"PRId64" bytes\n", hm_pow(power));
        pba_clear(&pba);
        hm_run_tracktotrack_once(&pba, &buffer, hm_pow(power), probe_count);
        hm_analyze(&pba, &results);
        if (results.is_uniform) {
          hm_print_tracktotrack_results(&results, hm_pow(power));
          break;
        }
      }
    }

    if (power == -1) {
      die("Couldn't detect correct --maxcylsize value. Is this raw HDD device?\n");
    }
  }

  if (dump_file) {
    pba_dump_all(&pba, dump_file, test->fields);
  }
  
  buffer_deinit(&buffer);
  pba_deinit(&pba);
}


/*********************************** COMMAND LINE ********************************************/

static void print_help() {
  report(
    "Usage: drvperf [options] <test> <path>                                          \n"
    "       drvperf --help                                                           \n"
    "       drvperf --version                                                        \n"
    "                                                                                \n"
    "Tests:                                                                          \n"
    "  seqread         sequential access performance [MB/s]                          \n"
    "  seqwrite                                                                      \n"
    "                                                                                \n"
    "  rndread         random access performance [IOPS, ms/request]                  \n"
    "  rndwrite                                                                      \n"
    "                                                                                \n"
    "  cncread         (SSD or RAID) determine optimal concurrency factor            \n"
    "  cncwrite                                                                      \n"
    "                                                                                \n"
    "  fullstroke      (HDD specific) determine fullstroke seek time [ms]            \n"
    "                  and rotational speed [RPM]                                    \n"
    "                                                                                \n"
    "  tracktotrack    (HDD specific) determine track-to-track seek time [ms]        \n"
    "                  and rotational speed [RPM]                                    \n"
    "                                                                                \n"
    "Options:                                                                        \n"
    "  --align <bytes>              align probe offsets                              \n"
    "  --debug                      turn on printing debug messages                  \n"
    "  --cache {bypass|drop|keep}   how to deal with page cache                      \n"
    "  --concurrent <number>        max number of concurrently executed requests     \n"
    "  --dump-file <path>           dump probes to specified file in .tsv format     \n"
    "  --force                      disable sanity checks                            \n"
    "  --help                       show this help                                   \n"
    "  --max-buffer-size <bytes>    max size of single operation buffer              \n"
    "  --maxcylsize {<bytes>|auto}  size of the largest cylinder                     \n"
    "  --method {auto|bio|kaio}     method of performing probes                      \n"
    "  --probe-length <bytes>       number of bytes to read/write with each probe    \n"
    "  --probes <count>             number of probes to make                         \n"
    "  --rndseed <number>           positive number used as random seed              \n"
    "  --sync {none|sync|dsync}     synchronization guarantees                       \n"
    "  --version                    print version number                             \n"
    "  --window-begin <bytes>       lowest allowed offset                            \n"
    "  --window-end <bytes>         highest allowed offset (exclusive)               \n"
    "  --window-length <bytes>      allowed offset range length                      \n"
    "                                                                                \n"
    "Full help including examples is provided by the manpage: `man -l drvperf.1'     \n"
  );
}

static void print_version() {
  report("drvperf/%u.%u (%s)\n", VER_MAJOR, VER_MINOR, VER_DATE);
  report("Written by Andrei Gudkov <gudokk@gmail.com>\n");
}

enum unit_id {
  U_B = 0,
  U_KB, U_MB, U_GB, U_TB, U_PB,
  U_KIB, U_MIB, U_GIB, U_TIB, U_PIB
};

struct unit_t {
  enum unit_id id;
  const char* str;
  int64_t coef;
};

static const struct unit_t UNITS[] = {
  [U_B] =  {U_B, "B", 1},
  
  [U_KB] = {U_KB, "KB", 1000LL},
  [U_MB] = {U_MB, "MB", 1000LL*1000},
  [U_GB] = {U_GB, "GB", 1000LL*1000*1000},
  [U_TB] = {U_TB, "TB", 1000LL*1000*1000*1000},
  [U_PB] = {U_PB, "PB", 1000LL*1000*1000*1000*1000},
  
  [U_KIB] = {U_KIB, "KiB", 1LL<<10},
  [U_MIB] = {U_MIB, "MiB", 1LL<<20},
  [U_GIB] = {U_GIB, "GiB", 1LL<<30},
  [U_TIB] = {U_TIB, "TiB", 1LL<<40},
  [U_PIB] = {U_PIB, "PiB", 1LL<<50}
};

struct number_t {
  enum {
    TYPE_INT64,
    TYPE_DOUBLE
  } type;

  union {
    int64_t i64_value;
    double  dbl_value;
  };
};


/*
 * Converts beginning of ${ptr} into int64 ${value} and advances ${ptr}.
 * If conversion fails then both ${ptr} and ${value} are left unchanged.
 * Format: (-|+)?[0-9]+
 */
static bool consume_int64(const char** ptr, int64_t* value) {
  char buf[32];
  size_t len = 0;
  int ndigits = 0;
  const char* p = *ptr;

  // optional sign
  if (*p == '-' || *p == '+') {
    buf[len++] = *p++;
  }
  // digits
  while (*p >= '0' && *p <= '9') {
    if (len >= sizeof(buf)) {
      return false;
    }
    buf[len++] = *p++;
    ndigits++;
  }
  // NULL
  buf[len] = '\0';

  if (ndigits < 1) {
    return false;
  }

  char* end;
  errno = 0;
  int64_t tmp_value = strtoll(buf, &end, 10);
  if (errno != 0 || end != buf+len) {
    return false;
  }
  *value = tmp_value;
  *ptr += len;
  return true;
}


/*
 * Converts beginning of ${ptr} into double ${value} and advances ${ptr}.
 * If conversion fails then both ${ptr} and ${value} are left unchanged.
 * Format: (-|+)?([0-9]*.[0-9]*) with at least one digit
 */
static bool consume_double(const char** ptr, double* value) {
  char buf[128];
  size_t len = 0;
  int ndigits = 0;
  int ndots = 0;
  const char* p = *ptr;

  // optional sign
  if (*p == '-' || *p == '+') {
    buf[len++] = *p++;
  }
  // digits and dots
  while ((*p >= '0' && *p <= '9') || *p == '.') {
    if (*p == '.') {
      if (ndots > 0) {
        break;
      }
      ndots++;
    } else {
      ndigits++;
    }
    if (len >= sizeof(buf)) {
      return false;
    }
    buf[len++] = *p++;
  }
  // NULL
  buf[len] = '\0';

  if (ndigits < 1 || ndots != 1) {
    return false;
  }

  char* end;
  errno = 0;
  double tmp_value = strtod(buf, &end);
  if (errno != 0 || end != buf+len) {
    return false;
  }
  *value = tmp_value;
  *ptr += len;
  return true;
}

/*
 * Converts beginning of ${ptr} into int64 or double ${number} and advances ${ptr}.
 * If conversion fails then both ${ptr} and ${unit} are left unchanged.
 */
static bool consume_number(const char** ptr, struct number_t* number) {
  const char* i64_ptr = *ptr;
  int64_t i64_value;
  bool i64_valid = consume_int64(&i64_ptr, &i64_value);

  const char* dbl_ptr = *ptr;
  double dbl_value;
  bool dbl_valid = consume_double(&dbl_ptr, &dbl_value);

  if (i64_valid && (!dbl_valid || i64_ptr >= dbl_ptr)) {
    number->type = TYPE_INT64;
    number->i64_value = i64_value;
    *ptr = i64_ptr;
    return true;

  } else if (dbl_valid) {
    number->type = TYPE_DOUBLE;
    number->dbl_value = dbl_value;
    *ptr = dbl_ptr;
    return true;

  } else {
    return false;

  }
}


/*
 * Converts beginning of ${ptr} into ${unit} and advances ${ptr}.
 * If conversion fails then both ${ptr} and ${unit} are left unchanged.
 */
static bool consume_unit(const char** ptr, const struct unit_t** unit) {
  
  struct conv_t {
    char c;
    enum unit_id bin_unit;
    enum unit_id dcm_unit;
  } convs[] = {
    {'b', U_B,   U_B},
    {'k', U_KIB, U_KB},
    {'m', U_MIB, U_MB},
    {'g', U_GIB, U_GB},
    {'t', U_TIB, U_TB},
    {'p', U_PIB, U_PB}
  };
  
  const char* p = *ptr;
  struct conv_t* conv = NULL;
  bool is_binary = false;
  
  if (!p) {
    return false;
  }
  char c = tolower(*(p++));
  for (int i = 0; i < arrlen(convs); i++) {
    if (convs[i].c == c) {
      conv = &convs[i];
      break;
    }
  }
  if (!conv) {
    return false;
  }
  if (conv->bin_unit != U_B) {
    if (!p) {
      return false;
    }
    c = *(p++);
    if (c == 'i' || c == 'I') {
      is_binary = true;
      if (!p) {
        return false;
      }
      c = *(p++);
    }
    if (c != 'b' && c != 'B') {
      return false;
    }
  }
  
  if (is_binary) {
    *unit = &UNITS[conv->bin_unit];
  } else {
    *unit = &UNITS[conv->dcm_unit];
  }
  *ptr = p;
  return true;
}

static bool consume_eof(const char** ptr) {
  if (**ptr) {
    return false;
  }
  return true;
}

static bool consume_pct(const char** ptr) {
  if (**ptr != '%') {
    return false;
  }
  (*ptr)++;
  return true;
}

/* 
 * Parses ${ptr} as ordinary int64_t number.
 * Format: <int64_t> <eof>
 */
static bool parse_int64(const char* ptr, int64_t* value,
                        int64_t min_value, int64_t max_value) {
  int64_t tmp_value;
  if (!consume_int64(&ptr, &tmp_value)) {
    return false;
  }
  if (!consume_eof(&ptr)) {
    return false;
  }

  if (tmp_value < min_value || tmp_value > max_value) {
    return false;
  }
  *value = tmp_value;
  return true;
}

/* 
 * Parses ${ptr} as absolute byte count value (4096, 4kib, 2.5mb).
 * Format: (<int64_t>|<double>) <unit>? <eof> 
 */
static bool parse_byte_count(const char* ptr, int64_t* value,
                             int64_t min_value, int64_t max_value) {

  struct number_t number;
  const struct unit_t* unit = &UNITS[U_B];
  if (!consume_number(&ptr, &number)) {
    return false;
  }
  consume_unit(&ptr, &unit); // optional
  if (!consume_eof(&ptr)) {
    return false;
  }

  int64_t tmp_value;
  switch (number.type) {
    case TYPE_INT64:
      if (number.i64_value > INT64_MAX / unit->coef) {
        return false;
      }
      tmp_value = number.i64_value * unit->coef;
      break;
    case TYPE_DOUBLE:
      tmp_value = to_int64(round(number.dbl_value * unit->coef));
      break;
    default:
      return false;
  }
  if (tmp_value < min_value || tmp_value > max_value) {
    return false;
  }
  *value = tmp_value;
  return true;
}

/* 
 * Parses ${ptr} as percentage (15.5%).
 * Format: (<int64_t>|<double>) <%> <eof> 
 */
static bool parse_percentage(const char* ptr, double* rel_value, 
                             double min_value, double max_value) {
  struct number_t value;
  if (!consume_number(&ptr, &value)) {
    return false;
  }
  if (!consume_pct(&ptr)) {
    return false;
  }
  if (!consume_eof(&ptr)) {
    return false;
  }

  double tmp_value;
  switch (value.type) {
    case TYPE_INT64:
      tmp_value = value.i64_value / 100.0;
      break;
    case TYPE_DOUBLE:
      tmp_value = value.dbl_value / 100.0;
      break;
    default:
      return false;
  }
  if (tmp_value < min_value || tmp_value > max_value) {
    return false;
  }
  *rel_value = tmp_value;
  return true;
}


enum cmd_status_id {
  CMD_UNSPECIFIED,
  CMD_PRINT_HELP,
  CMD_PRINT_VERSION,
  CMD_RUN_TEST
};

static enum cmd_status_id parse_cmdline(int argc, char* argv[]) {
  
  static struct option opts[] = {
    { "debug",           no_argument,       NULL, 'a' },
    { "probes",          required_argument, NULL, 'b' },
    { "probe-length",    required_argument, NULL, 'c' },
    { "help",            no_argument,       NULL, 'd' },
    { "version",         no_argument,       NULL, 'e' },
    { "cache",           required_argument, NULL, 'f' },
    { "align",           required_argument, NULL, 'g' },
    { "concurrent",      required_argument, NULL, 'h' },
    { "window-begin",    required_argument, NULL, 'i' },
    { "window-end",      required_argument, NULL, 'j' },
    { "window-length",   required_argument, NULL, 'k' },
    { "dump-file",       required_argument, NULL, 'l' },
    { "force",           no_argument,       NULL, 'm' },
    { "maxcylsize",      required_argument, NULL, 'n' },
    { "method",          required_argument, NULL, 'o' },
    { "sync",            required_argument, NULL, 'p' },
    { "max-buffer-size", required_argument, NULL, 'r' },
    { "rndseed",         required_argument, NULL, 's' },
    { NULL,              0,                 NULL,  0  }
  };
  
  if (argc <= 1) {
    return CMD_UNSPECIFIED;
  }
  
  int c;
  opterr = 0;
  while ((c = getopt_long_only(argc, argv, ":", opts, NULL)) != -1) {
    switch (c) {
      case 'a': {
        debug = true;
        break;
      }
      case 'b': {
        if (!parse_int64(optarg, &probe_count, 1, INT64_MAX)) {
          die_help("Invalid --probes value: `%s'\n", optarg);
        }
        break;
      }
      case 'c': {
        if (!parse_byte_count(optarg, &probe_length, 1, INT64_MAX)) {
          die_help("Invalid --probe-length value: `%s'\n", optarg);
        }
        break;
      }
      case 'd': {
        // won't parse options any further
        return CMD_PRINT_HELP;
      }
      case 'e': {
        // won't parse options any further
        return CMD_PRINT_VERSION;
      }
      case 'f': {
        bool found = false;
        for (int64_t i = 0; i < arrlen(CACHE_POLICY); i++) {
          if (!strcmp(CACHE_POLICY[i].name, optarg)) {
            cache_policy = &CACHE_POLICY[i];
            found = true;
            break;
          }
        }
        if (!found) {
          die_help("Invalid --cache value: `%s'\n", optarg);
        }
        break;
      }
      case 'g': {
        if (!parse_byte_count(optarg, &offset_alignment, 1, INT64_MAX)) {
          die_help("Invalid --align value: `%s'\n", optarg);
        }
        break;
      }
      case 'h': {
        if (!parse_int64(optarg, &concurrent, 1, INT64_MAX)) {
          die_help("Invalid --concurrent value: `%s'\n", optarg);
        }
        break;
      }
      case 'i': {
        if (!parse_byte_count(optarg, &window_begin, 0, INT64_MAX)) {
          if (!parse_percentage(optarg, &window_begin_rel, 0.0, 1.0)) {
            die_help("Invalid --window-begin value: `%s'\n", optarg);
          }
        }
        break;
      }
      case 'j': {
        if (!parse_byte_count(optarg, &window_end, 0, INT64_MAX)) {
          if (!parse_percentage(optarg, &window_end_rel, 0.0, 1.0)) {
            die_help("Invalid --window-end value: `%s'\n", optarg);
          }
        }
        break;
      }
      case 'k': {
        if (!parse_byte_count(optarg, &window_length, 0, INT64_MAX)) {
          if (!parse_percentage(optarg, &window_length_rel, 0.0, 1.0)) {
            die_help("Invalid --window-length value: `%s'\n", optarg);
          }
        }
        break;
      }
      case 'l': {
        dump_file = optarg;
        break;
      }
      case 'm': {
        force = true;
        break;
      }
      case 'n': {
        if (strcmp(optarg, "auto") == 0) {
          maxcylsize = -1;
        } else if (!parse_byte_count(optarg, &maxcylsize, 1, INT64_MAX)) {
          die_help("Invalid --maxcylsize value: `%s'\n", optarg);
        }
        break;
      }
      case 'o': {
        bool found = false;
        for (int64_t i = 0; i < arrlen(METHODS); i++) {
          if (strcmp(optarg, METHODS[i].name) == 0) {
            method = &METHODS[i];
            found = true;
            break;
          }
        }
        if (!found) {
          die_help("Invalid --method value: `%s'n", optarg);
        }
        break;
      }
      case 'p': {
        bool found = false;
        for (int64_t i = 0; i < arrlen(SYNC_POLICY); i++) {
          if (!strcmp(SYNC_POLICY[i].name, optarg)) {
            sync_policy = &SYNC_POLICY[i];
            found = true;
            break;
          }
        }
        if (!found) {
          die_help("Invalid --sync value: `%s'\n", optarg);
        }
        break;
      }
      case 'r': {
        if (!parse_byte_count(optarg, &max_buffer_size, 1, INT64_MAX)) {
          die_help("Invalid --max-buffer-size value: `%s'\n", optarg);
        }
        break;
      }
      case 's': {
        if (!parse_int64(optarg, &rndseed, 1, INT32_MAX)) {
          die_help("Invalid --rndseed value: `%s'\n", optarg);
        }
        break;
      }
      case ':': {
        die_help("Option `%s' requires argument\n", argv[optind-1]);
      }
      case '?': {
        die_help("Unknown option `%s'\n", argv[optind-1]);
      }
      default: {
        die_help("Error parsing arguments\n");
      }
    }
  }
  
  // test name
  if (optind < argc) {
    for (int64_t i = 0; i < arrlen(TESTS); i++) {
      if (strcmp(argv[optind], TESTS[i].name) == 0) {
        test = &TESTS[i];
        break;
      }
    }
    if (test == NULL) {
      die_help("Invalid test name: `%s'\n", argv[optind]);
    }
  } else {
    die_help("Test name not specified\n");
  }
  optind++;
  
  // path
  if (optind < argc) {
    target_path = argv[optind];
  } else {
    die_help("Path not specified\n");
  }
  optind++;
  
  // tail
  if (optind < argc) {
    die_help("Too many arguments\n");
  }

  return CMD_RUN_TEST;
}

/*
 * Resolves ${rel_value} against ${rel_base}.
 */
static int64_t resolve_int64(int64_t abs_value, double rel_value, int64_t rel_base) {
  if (abs_value != -1) {
    return abs_value;
  } else if (!isnan(rel_value)) {
    return to_int64(round(rel_value * rel_base));
  } else {
    return -1;
  }
}

/*
 * Resolves ${window_begin}, ${window_end}, ${window_length} to defined absolute values.
 * If resolution is not possible for some reason, variables are left unchanged.
 */
static bool resolve_window() {
  int64_t tmp_window_begin  = resolve_int64(window_begin,  window_begin_rel,  file_length);
  int64_t tmp_window_end    = resolve_int64(window_end,    window_end_rel,    file_length);
  int64_t tmp_window_length = resolve_int64(window_length, window_length_rel, file_length);

  // window_begin
  if (tmp_window_begin == -1) {
    if (tmp_window_end != -1 && tmp_window_length != -1) {
      if (tmp_window_end < tmp_window_length) {
        return false;
      }
      tmp_window_begin = tmp_window_end - tmp_window_length;
    } else {
      tmp_window_begin = 0;
    }
  }
  assert(tmp_window_begin >= 0);
  
  // window_end
  if (tmp_window_end == -1) {
    if (tmp_window_length != -1) {
      if (INT64_MAX - tmp_window_begin < tmp_window_length) {
        return false;
      }
      tmp_window_end = tmp_window_begin + tmp_window_length;
    } else {
      tmp_window_end = file_length;
    }
  }
  assert(tmp_window_end >= 0);
  
  // window_length
  if (tmp_window_length == -1) {
    if (tmp_window_end < tmp_window_begin) {
      return false;
    }
    tmp_window_length = tmp_window_end - tmp_window_begin;
  }
  assert(tmp_window_length >= 0);
  
  
  if (tmp_window_end - tmp_window_length != tmp_window_begin) {
    return false;
  }
  if (tmp_window_end > file_length) {
    return false;
  }

  window_begin = tmp_window_begin;
  window_end = tmp_window_end;
  window_length = tmp_window_length;
 
  return true;
}

void resolve_settings() {
  // probe_count: 1) cmdline; 2) default value for chosen test
  if (probe_count <= 0) {
    probe_count = test->default_probe_count;
    if (probe_count <= 0) {
      die_help("Couldn't figure out --probes value\n");
    }
  }
  
  // concurrent
  if (concurrent > 1) {
    if (test->id != TN_RANDOM_READ && test->id != TN_RANDOM_WRITE) {
      die_help("--concurrent is compatible only with `%s' and `%s' tests\n",
          TESTS[TN_RANDOM_READ].name, TESTS[TN_RANDOM_WRITE].name); 
    }
  }


  // probe_length: 1) cmdline; 2) default value for chosen test; 3) blockdev settings
  if (probe_length <= 0) {
    probe_length = test->default_probe_length;
    if (probe_length <= 0) {
      probe_length = max3(bdev->minimal_io_size, bdev->logical_sector_size, bdev->physical_sector_size);
      if (probe_length <= 0) {
        die_help("Couldn't figure out --probe-length value\n");
      }
    }
  }
 
  // offset_alignment: 1) cmdline; 2) blockdev
  if (offset_alignment <= 0) {
    offset_alignment = max3(bdev->minimal_io_size, bdev->logical_sector_size, bdev->physical_sector_size);
    if (offset_alignment <= 0) {
      die_help("Couldn't figure out --align value\n");
    }
  }
  
  // window_*
  if (!resolve_window()) {
    die_help("Invalid window\n");
  }
  if ((window_end - probe_length) / offset_alignment * offset_alignment < window_begin) {
    die_help("Window is too small for given --probe-length and --align\n");
  }
}


/*********************************** APPLICATION ********************************************/

static void perform_sanity_checks(struct bdev_t* bdev) {
  
# define sanity_report(fmt_fatal, fmt_warn, ...) \
    if (!force) { \
      die(fmt_fatal, ##__VA_ARGS__); \
    } else { \
      warn(fmt_warn, ##__VA_ARGS__); \
    }

  if (test->operation->id == OP_WRITE) {
    if (bdev->mount_point) {
      sanity_report(
          "Won't write to raw device `%s' which is mounted at `%s'. Unmount first or use --force\n",
          "Writing to raw device `%s' which is mounted at `%s' (forced)\n",
          bdev->name,
          bdev->mount_point
      );
    }
    if (bdev->pt_children.length > 0) {
      char* names = bdl_join_names(&bdev->pt_children);
      sanity_report(
        "Won't write to raw device `%s' which contains partitions [%s], delete partitions first or use --force\n",
        "Writing to raw device `%s' which contains partitions [%s] (forced)\n",
        bdev->name,
        names
      );
      free(names);
    }
    if (bdev->md_master) {
      sanity_report(
        "Won't write to raw device `%s' which has RAID %s built atop of it, disassemble array first or use --force\n",
        "Writing to raw device `%s' which has RAID %s built atop of it (forced)\n",
        bdev->name,
        bdev->md_master->name
      );
    }
  }
# undef sanity_report 
}

static void run_test() {
  
  struct bdl_t bdl = bdl_null;
  bdl_list_all_devices(&bdl);
  if (debug) {
    bdl_dump_all(&bdl);
  }
  
  int flags = 0;
  flags |= test->operation->open_mode;
  flags |= sync_policy->open_flags;
  flags |= cache_policy->open_flags;
  file_fd = open(target_path, flags);
  if (file_fd == -1) {
    die("open(%s): %s\n", target_path, strerror(errno));
  }
  
  struct stat st;
  do {
    if (lstat(target_path, &st) == -1) {
      die("stat(%s): %s\n", target_path, strerror(errno));
    }
 
    switch (st.st_mode & S_IFMT) {
      case S_IFBLK: {
        bdev = bdl_find(&bdl, st.st_rdev);
        if (!bdev) {
          die("Couldn't find device %d:%d in sysfs\n", major(st.st_rdev), minor(st.st_rdev));
        }
        file_length = bdev->size;
        perform_sanity_checks(bdev);
        break;
      }
      case S_IFREG: {
        bdev = bdl_find(&bdl, st.st_dev);
        if (!bdev) {
          die("Couldn't find device %d:%d in sysfs\n", major(st.st_rdev), minor(st.st_rdev));
        }
        file_length = st.st_size;
        break;
      }
      case S_IFLNK: {
        static char target_path_buf[PATH_MAX];
        if (realpath(target_path, target_path_buf) == NULL) {
          die("Failed to resolve symlink %s\n", target_path);
        }
        target_path = target_path_buf;
        warn("Target path is symlink, resolved to `%s'\n", target_path);
        break;
      }
      default: {
        die("Unsupported type of file\n");
      }
    }
  } while ((st.st_mode & S_IFMT) == S_IFLNK);
  
  resolve_settings();

  if (debug) {
    sc_dump_sysconf_vars();
    dump_settings_vars();
    dump_context_vars();
  }
  
  if (cache_policy->id == CP_DROP) {
    int64_t ts_begin = now_nanoes();
    sync_buffers(file_fd);
    drop_caches();
    int64_t ts_end = now_nanoes();
    report("Page cache dropped in %.3f s.\n", (ts_end-ts_begin)/1E9);
  }

  test->func();

  if (test->operation->id == OP_WRITE) {
    int64_t ts_begin = now_nanoes();
    sync_buffers(file_fd);
    int64_t ts_end = now_nanoes();
    report("Completed fsync() in %.3f s.\n", (ts_end-ts_begin)/1E9);
  }

  close(file_fd);
  bdl_deinit(&bdl);
}

int main(int argc, char* argv[]) {
  setlinebuf(stdout);
  setlocale(LC_ALL, ""); // for digit group separator
  sc_query_sysconf();
  rndseed = now_nanoes();

  int status = EXIT_SUCCESS;
  switch (parse_cmdline(argc, argv)) {
    case CMD_UNSPECIFIED:
      print_help();
      status = EXIT_FAILURE;
      break;
    case CMD_PRINT_HELP:
      print_help();
      break;
    case CMD_PRINT_VERSION:
      print_version();
      break;
    case CMD_RUN_TEST:
      rnd_seed(to_uint32(rndseed));
      run_test();
      break;
  }
  exit(status);
  return 0;
}

