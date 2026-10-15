# ewfcompare: e01-rs against libewf

A head-to-head read benchmark. `ewfcompare.c` drives e01-rs (as a static
library, through its C API) and libewf through one small vtable, so the same
workload code runs against both and only the library underneath differs.

Every workload folds the bytes it read into a checksum and prints it as
`sum=`. The same workload must print the same sum for both backends: that is
the check that e01-rs returned the right bytes, not just returned them fast.

## Building

Needs libewf and The Sleuth Kit with headers (MacPorts' `libewf` and
`sleuthkit`, or your distribution's `-dev` packages):

```sh
PREFIX=/opt/local e01/compare/build.sh
```

## Running

```sh
e01/compare/ewfcompare e01rs  image.E01 rand 4 100000
e01/compare/ewfcompare libewf image.E01 rand 4 100000

# every workload, both backends, interleaved:
e01/compare/matrix.sh image.E01 [more.E01 ...]
WORKLOADS="open seq64k tsk-walk" e01/compare/matrix.sh image.E01
```

| workload | what it does |
|---|---|
| `open REPS` | open, read the first sector, close; best and median |
| `seq KIB [LIMIT_MIB]` | read front to back in KIB-sized reads |
| `rand KIB COUNT [SPAN_MIB] [ALIGN] [SEED]` | random reads within the first SPAN MiB |
| `mt THREADS KIB COUNT` | random reads from THREADS threads at once |
| `tsk-walk` | TSK: walk every directory of every filesystem (`fls -r`) |
| `tsk-read` | TSK: walk, and read the content of every allocated file |

`mt` shares one e01-rs reader between its threads, since `read_at_offset`
takes `&self`. libewf serializes reads on a handle behind a lock, so it gets a
handle per thread instead, which is its fastest arrangement.

The TSK workloads open the image through TSK's own EWF support for libewf and
through `tsk_img_open_external` for e01-rs, then run identical TSK code.

Numbers are only comparable with a warm page cache; `matrix.sh` interleaves
the backends so neither consistently runs second.
