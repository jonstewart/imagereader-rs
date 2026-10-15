/*
 * Head-to-head read benchmark: e01-rs (through its C API) against libewf.
 *
 * Both backends sit behind the same tiny vtable and are driven by the same
 * workload code, so the numbers differ only by the library underneath. Every
 * workload also folds what it read into a checksum, printed alongside the
 * timing: run the same workload against both backends and the checksums must
 * match, or one of them returned the wrong bytes.
 *
 * The TSK workloads use The Sleuth Kit on top of each backend -- libewf via
 * TSK's own EWF support, e01-rs via tsk_img_open_external -- so they measure
 * what a forensic tool built on either library would see.
 *
 * Build with ./build.sh; run ./ewfcompare -h for the workloads.
 */

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libewf.h>
#include <tsk/libtsk.h>

/* ---- e01-rs C API (mirrors e01/src/capi.rs) ---------------------------- */

typedef struct E01Error {
  char* message;
} E01Error;

typedef struct E01ReaderOptions {
  int corrupt_section_policy;
  int corrupt_chunk_policy;
} E01ReaderOptions;

typedef struct E01Handle {
  void* reader;
  const char* const* segment_paths;
  size_t segment_paths_count;
  size_t chunk_size;
  size_t chunk_count;
  size_t sector_count;
  size_t sector_size;
  uint64_t image_size;
  const uint8_t* stored_md5;
  const uint8_t* stored_sha1;
} E01Handle;

extern E01Handle* e01_open_glob(const char* path, const E01ReaderOptions* opts,
                                E01Error** err);
extern void e01_close(E01Handle* h);
extern size_t e01_read(E01Handle* h, uint64_t off, char* buf, size_t len,
                       E01Error** err);
extern void e01_free_error(E01Error* err);

/* ---- backend vtable ----------------------------------------------------- */

typedef struct Backend {
  const char* name;
  void* (*open)(const char* path);
  /* Returns bytes read, or -1. */
  int64_t (*read)(void* h, uint64_t off, void* buf, size_t len);
  uint64_t (*size)(void* h);
  void (*close)(void* h);
  /* Whether one handle may be shared by concurrent readers. */
  int shareable;
} Backend;

static void die(const char* msg) {
  fprintf(stderr, "fatal: %s\n", msg);
  exit(2);
}

/* libewf */

typedef struct EwfH {
  libewf_handle_t* h;
  uint64_t size;
} EwfH;

static void* ewf_open(const char* path) {
  libewf_error_t* err = NULL;
  char** names = NULL;
  int n = 0;
  if (libewf_glob(path, strlen(path), LIBEWF_FORMAT_UNKNOWN, &names, &n, &err) != 1) {
    libewf_error_backtrace_fprint(err, stderr);
    die("libewf_glob");
  }
  EwfH* e = calloc(1, sizeof *e);
  if (libewf_handle_initialize(&e->h, &err) != 1) die("libewf_handle_initialize");
  if (libewf_handle_open(e->h, names, n, LIBEWF_OPEN_READ, &err) != 1) {
    libewf_error_backtrace_fprint(err, stderr);
    die("libewf_handle_open");
  }
  libewf_glob_free(names, n, NULL);
  if (libewf_handle_get_media_size(e->h, &e->size, &err) != 1) die("media size");
  return e;
}

static int64_t ewf_read(void* h, uint64_t off, void* buf, size_t len) {
  EwfH* e = h;
  libewf_error_t* err = NULL;
  ssize_t r = libewf_handle_read_buffer_at_offset(e->h, buf, len, (off64_t)off, &err);
  if (r < 0) {
    libewf_error_backtrace_fprint(err, stderr);
    libewf_error_free(&err);
    return -1;
  }
  return r;
}

static uint64_t ewf_size(void* h) { return ((EwfH*)h)->size; }

static void ewf_close(void* h) {
  EwfH* e = h;
  libewf_handle_close(e->h, NULL);
  libewf_handle_free(&e->h, NULL);
  free(e);
}

/* e01-rs */

static void* rs_open(const char* path) {
  E01ReaderOptions opts = {0 /* CSP_ERROR */, 0 /* CCP_ERROR */};
  E01Error* err = NULL;
  E01Handle* h = e01_open_glob(path, &opts, &err);
  if (!h) {
    fprintf(stderr, "e01_open_glob: %s\n", err ? err->message : "?");
    die("e01_open_glob");
  }
  return h;
}

static int64_t rs_read(void* h, uint64_t off, void* buf, size_t len) {
  E01Error* err = NULL;
  size_t r = e01_read(h, off, buf, len, &err);
  if (err) {
    fprintf(stderr, "e01_read @%" PRIu64 ": %s\n", off, err->message);
    e01_free_error(err);
    return -1;
  }
  return (int64_t)r;
}

static uint64_t rs_size(void* h) { return ((E01Handle*)h)->image_size; }
static void rs_close(void* h) { e01_close(h); }

/* libewf serializes concurrent reads on one handle behind a lock, so it is
 * marked unshareable: the threaded workload gives it a handle per thread,
 * which is its fastest configuration. */
static const Backend BACKENDS[] = {
    {"libewf", ewf_open, ewf_read, ewf_size, ewf_close, 0},
    {"e01rs", rs_open, rs_read, rs_size, rs_close, 1},
};

/* ---- helpers ------------------------------------------------------------ */

static double now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Order-sensitive 64-bit checksum, cheap enough not to dominate a read loop:
 * one multiply-add per 8 bytes. */
static uint64_t fold(uint64_t acc, const void* p, size_t n) {
  const uint8_t* b = p;
  size_t i = 0;
  for (; i + 8 <= n; i += 8) {
    uint64_t w;
    memcpy(&w, b + i, 8);
    acc = (acc ^ w) * 0x100000001b3ULL + 0x9e3779b97f4a7c15ULL;
  }
  for (; i < n; i++) acc = (acc ^ b[i]) * 0x100000001b3ULL;
  return acc;
}

static uint64_t splitmix(uint64_t* s) {
  uint64_t z = (*s += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

static int checksums = 1;

static void report(const char* backend, const char* workload, double secs,
                   uint64_t bytes, uint64_t ops, uint64_t sum) {
  printf("%-7s %-28s %9.3fs %10.1f MiB/s %10.0f ops/s  sum=%016" PRIx64 "\n",
         backend, workload, secs, bytes / 1048576.0 / secs, ops / secs, sum);
  fflush(stdout);
}

/* ---- raw read workloads ------------------------------------------------- */

static int cmp_double(const void* a, const void* b) {
  double x = *(const double*)a, y = *(const double*)b;
  return (x > y) - (x < y);
}

/* Open, read the first sector, close. Reports the best and the median, in
 * milliseconds: an open is a few ms, which the seconds columns cannot show. */
static void w_open(const Backend* be, const char* path, int reps) {
  double* t = calloc(reps, sizeof *t);
  for (int i = 0; i < reps; i++) {
    double t0 = now();
    void* h = be->open(path);
    char buf[512];
    if (be->read(h, 0, buf, sizeof buf) != sizeof buf) die("read");
    be->close(h);
    t[i] = now() - t0;
  }
  qsort(t, reps, sizeof *t, cmp_double);
  printf("%-7s %-28s %9.3fms best %9.3fms median  (%d reps)\n", be->name, "open+read+close",
         t[0] * 1e3, t[reps / 2] * 1e3, reps);
  fflush(stdout);
  free(t);
}

static void w_seq(const Backend* be, const char* path, size_t rsize, uint64_t limit) {
  void* h = be->open(path);
  uint64_t size = be->size(h);
  if (limit && limit < size) size = limit;
  char* buf = malloc(rsize);
  uint64_t sum = 0, ops = 0, off = 0;
  double t0 = now();
  while (off < size) {
    size_t want = size - off < rsize ? size - off : rsize;
    int64_t n = be->read(h, off, buf, want);
    if (n <= 0) die("seq read");
    if (checksums) sum = fold(sum, buf, n);
    off += n;
    ops++;
  }
  double t = now() - t0;
  char name[64];
  snprintf(name, sizeof name, "seq %zuK", rsize / 1024);
  report(be->name, name, t, off, ops, sum);
  free(buf);
  be->close(h);
}

/* Random reads at `align`-aligned offsets within the first `span` bytes. */
static void w_rand(const Backend* be, const char* path, size_t rsize, uint64_t count,
                   uint64_t span, uint64_t align, uint64_t seed) {
  void* h = be->open(path);
  uint64_t size = be->size(h);
  if (!span || span > size) span = size;
  uint64_t slots = (span - rsize) / align;
  char* buf = malloc(rsize);
  uint64_t s = seed, sum = 0, bytes = 0;
  double t0 = now();
  for (uint64_t i = 0; i < count; i++) {
    uint64_t off = (splitmix(&s) % slots) * align;
    int64_t n = be->read(h, off, buf, rsize);
    if (n != (int64_t)rsize) die("rand read");
    if (checksums) sum = fold(sum ^ off, buf, n);
    bytes += n;
  }
  double t = now() - t0;
  char name[64];
  snprintf(name, sizeof name, "rand %zuK span=%" PRIu64 "M%s", rsize / 1024, span >> 20,
           align % 4096 ? " unaligned" : "");
  report(be->name, name, t, bytes, count, sum);
  free(buf);
  be->close(h);
}

typedef struct MtArg {
  const Backend* be;
  const char* path;
  void* shared;
  size_t rsize;
  uint64_t count, slots, align, seed, sum, bytes;
} MtArg;

static void* mt_worker(void* p) {
  MtArg* a = p;
  void* h = a->shared ? a->shared : a->be->open(a->path);
  char* buf = malloc(a->rsize);
  uint64_t s = a->seed;
  for (uint64_t i = 0; i < a->count; i++) {
    uint64_t off = (splitmix(&s) % a->slots) * a->align;
    int64_t n = a->be->read(h, off, buf, a->rsize);
    if (n != (int64_t)a->rsize) die("mt read");
    if (checksums) a->sum += fold(off, buf, n); /* order-independent across threads */
    a->bytes += n;
  }
  free(buf);
  if (!a->shared) a->be->close(h);
  return NULL;
}

static void w_mt(const Backend* be, const char* path, int threads, size_t rsize,
                 uint64_t count, uint64_t align, uint64_t seed) {
  void* h = be->open(path);
  uint64_t size = be->size(h);
  void* shared = be->shareable ? h : NULL;
  MtArg args[256];
  pthread_t tids[256];
  if (threads > 256) die("too many threads");
  double t0 = now();
  for (int i = 0; i < threads; i++) {
    args[i] = (MtArg){be, path, shared, rsize, count / threads,
                      (size - rsize) / align, align, seed + i, 0, 0};
    pthread_create(&tids[i], NULL, mt_worker, &args[i]);
  }
  uint64_t sum = 0, bytes = 0, ops = 0;
  for (int i = 0; i < threads; i++) {
    pthread_join(tids[i], NULL);
    sum += args[i].sum;
    bytes += args[i].bytes;
    ops += args[i].count;
  }
  double t = now() - t0;
  be->close(h);
  char name[64];
  snprintf(name, sizeof name, "mt%d rand %zuK%s", threads, rsize / 1024,
           be->shareable ? "" : " (per-thr)");
  report(be->name, name, t, bytes, ops, sum);
}

/* ---- TSK workloads ------------------------------------------------------ */

/* Exported by libtsk but declared only in its internal headers. */
extern void* tsk_img_malloc(size_t len);
extern void tsk_img_free(void* img);

typedef struct RsImg {
  TSK_IMG_INFO info; /* must be first */
  E01Handle* h;
} RsImg;

static ssize_t rsimg_read(TSK_IMG_INFO* img, TSK_OFF_T off, char* buf, size_t len) {
  return (ssize_t)rs_read(((RsImg*)img)->h, (uint64_t)off, buf, len);
}

static void rsimg_close(TSK_IMG_INFO* img) {
  e01_close(((RsImg*)img)->h);
  tsk_img_free(img);
}

static void rsimg_stat(TSK_IMG_INFO* img, FILE* f) {
  (void)img;
  fprintf(f, "e01-rs\n");
}

static TSK_IMG_INFO* tsk_open(const Backend* be, const char* path) {
  if (be->open == ewf_open) {
    TSK_IMG_INFO* img = tsk_img_open_utf8_sing(path, TSK_IMG_TYPE_EWF_EWF, 0);
    if (!img) {
      tsk_error_print(stderr);
      die("tsk_img_open");
    }
    return img;
  }
  RsImg* r = tsk_img_malloc(sizeof *r);
  r->h = rs_open(path);
  TSK_IMG_INFO* img = tsk_img_open_external(r, r->h->image_size, 512, rsimg_read,
                                            rsimg_close, rsimg_stat);
  if (!img) {
    tsk_error_print(stderr);
    die("tsk_img_open_external");
  }
  return img;
}

typedef struct WalkState {
  uint64_t files, dirs, bytes, sum;
  int read_content;
  char* buf;
} WalkState;

static TSK_WALK_RET_ENUM walk_cb(TSK_FS_FILE* file, const char* path, void* p) {
  WalkState* st = p;
  if (!file->name) return TSK_WALK_CONT;
  st->sum = fold(st->sum, file->name->name, strlen(file->name->name));
  st->sum = fold(st->sum, path, strlen(path));
  if (file->meta) {
    st->sum = fold(st->sum, &file->meta->size, sizeof file->meta->size);
    if (file->meta->type == TSK_FS_META_TYPE_DIR) st->dirs++;
  }
  st->files++;
  if (st->read_content && file->meta && file->meta->type == TSK_FS_META_TYPE_REG &&
      (file->meta->flags & TSK_FS_META_FLAG_ALLOC) && file->name->type == TSK_FS_NAME_TYPE_REG) {
    TSK_OFF_T size = file->meta->size, off = 0;
    while (off < size) {
      ssize_t n = tsk_fs_file_read(file, off, st->buf, 65536, TSK_FS_FILE_READ_FLAG_NONE);
      if (n <= 0) break;
      st->sum = fold(st->sum, st->buf, n);
      st->bytes += n;
      off += n;
    }
  }
  return TSK_WALK_CONT;
}

static void walk_fs(TSK_IMG_INFO* img, TSK_OFF_T off, WalkState* st) {
  TSK_FS_INFO* fs = tsk_fs_open_img(img, off, TSK_FS_TYPE_DETECT);
  if (!fs) {
    tsk_error_reset();
    return;
  }
  tsk_fs_dir_walk(fs, fs->root_inum,
                  TSK_FS_DIR_WALK_FLAG_RECURSE | TSK_FS_DIR_WALK_FLAG_ALLOC |
                      TSK_FS_DIR_WALK_FLAG_UNALLOC,
                  walk_cb, st);
  tsk_error_reset();
  tsk_fs_close(fs);
}

static void w_tsk(const Backend* be, const char* path, int read_content) {
  WalkState st = {0};
  st.read_content = read_content;
  st.buf = malloc(65536);
  double t0 = now();
  TSK_IMG_INFO* img = tsk_open(be, path);
  TSK_VS_INFO* vs = tsk_vs_open(img, 0, TSK_VS_TYPE_DETECT);
  if (vs) {
    for (TSK_PNUM_T i = 0; i < vs->part_count; i++) {
      const TSK_VS_PART_INFO* part = tsk_vs_part_get(vs, i);
      if (part->flags & TSK_VS_PART_FLAG_ALLOC)
        walk_fs(img, part->start * vs->block_size, &st);
    }
    tsk_vs_close(vs);
  } else {
    tsk_error_reset();
    walk_fs(img, 0, &st);
  }
  tsk_img_close(img);
  double t = now() - t0;
  char name[64];
  snprintf(name, sizeof name, read_content ? "tsk read-all-files" : "tsk walk (fls -r)");
  report(be->name, name, t, st.bytes, st.files, st.sum);
  fprintf(stderr, "  %s: %" PRIu64 " names, %" PRIu64 " dirs, %" PRIu64 " content bytes\n",
          be->name, st.files, st.dirs, st.bytes);
  free(st.buf);
}

/* ---- main --------------------------------------------------------------- */

static void usage(void) {
  fprintf(stderr,
          "usage: ewfcompare [-n] BACKEND IMAGE WORKLOAD [ARGS...]\n"
          "  BACKEND : libewf | e01rs\n"
          "  -n      : skip checksumming what was read\n"
          "workloads:\n"
          "  open REPS\n"
          "  seq READ_KIB [LIMIT_MIB]\n"
          "  rand READ_KIB COUNT [SPAN_MIB] [ALIGN] [SEED]\n"
          "  mt THREADS READ_KIB COUNT [ALIGN] [SEED]\n"
          "  tsk-walk\n"
          "  tsk-read\n");
  exit(2);
}

int main(int argc, char** argv) {
  int a = 1;
  if (a < argc && !strcmp(argv[a], "-n")) {
    checksums = 0;
    a++;
  }
  if (argc - a < 3) usage();
  const Backend* be = NULL;
  for (size_t i = 0; i < sizeof BACKENDS / sizeof *BACKENDS; i++)
    if (!strcmp(argv[a], BACKENDS[i].name)) be = &BACKENDS[i];
  if (!be) usage();
  const char* path = argv[a + 1];
  const char* wl = argv[a + 2];
  char** rest = argv + a + 3;
  int nrest = argc - a - 3;
#define ARG(i, def) (nrest > (i) ? strtoull(rest[i], NULL, 0) : (def))

  if (!strcmp(wl, "open")) {
    w_open(be, path, (int)ARG(0, 5));
  } else if (!strcmp(wl, "seq")) {
    w_seq(be, path, ARG(0, 1024) * 1024, ARG(1, 0) << 20);
  } else if (!strcmp(wl, "rand")) {
    w_rand(be, path, ARG(0, 4) * 1024, ARG(1, 100000), ARG(2, 0) << 20, ARG(3, 4096),
           ARG(4, 42));
  } else if (!strcmp(wl, "mt")) {
    w_mt(be, path, (int)ARG(0, 8), ARG(1, 4) * 1024, ARG(2, 200000), ARG(3, 4096),
         ARG(4, 42));
  } else if (!strcmp(wl, "tsk-walk")) {
    w_tsk(be, path, 0);
  } else if (!strcmp(wl, "tsk-read")) {
    w_tsk(be, path, 1);
  } else {
    usage();
  }
  return 0;
}
