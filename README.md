# IPAS

IPAS is a small IPv4/IPv6 prefix-to-AS system written in C and started by Gianluca Mazzini in 2015.

The project is intentionally split into two independent components:

- `bgp3` is the only long-running process. It receives RIPE RIS Live updates, keeps an in-memory collision-free Patricia trie for fast live lookups, serves WHOIS-style queries on TCP port 43, and periodically checkpoints the persistent RAW database.
- `ipas.cgi` is a stateless CGI frontend. It reads the latest RAW snapshot directly from disk and provides summaries, offline IP lookups, ASN analysis and text exports. It never contacts `bgp3` and therefore does not take locks or consume query capacity from the collector.

The persistent `bgp.raw` file is the source of truth. Patricia tries, HTML views, statistics and text exports are all derived data and can be rebuilt from the RAW snapshot.

## Versions

- `bgp3.c`: Version 4.03
- `ipas.c`: Version 4.01

The version number of a program is increased only when its source file changes. Documentation, Makefile and other support-file changes do not change program versions.

## Architecture

```text
RIPE RIS Live
     |
     v
   bgp3  <---- WHOIS queries on TCP/43
     |
     v
  bgp.raw        persistent snapshot / source of truth
     |
     v
 ipas.cgi        stateless CGI, started only by the web server
     |
     +--> HTML summary
     +--> offline IPv4/IPv6 lookup
     +--> ASN analysis
     +--> IPv4 export
     +--> IPv6 export
```

Only `bgp3` is a daemon. `ipas.cgi` starts for one HTTP request, reads the RAW file, returns its result and exits.

## Requirements

Debian/Trixie example:

```sh
apt install build-essential libwebsockets-dev whois
```

`bgp3` links against libwebsockets and pthreads. `ipas.cgi` only uses the standard C/POSIX networking and file APIs.

## Build

```sh
make
```

This builds:

```text
bgp3
ipas.cgi
```

To remove generated binaries:

```sh
make clean
```

The Makefile currently builds with:

```text
-O3 -march=native -Wall -Wextra -std=gnu89
```

Because of `-march=native`, the binaries should normally be rebuilt on the machine where they will run rather than copied between different CPU generations.

## bgp3

### Purpose

`bgp3` maintains the live prefix database.

It:

1. loads an existing RAW snapshot if one exists;
2. rebuilds collision-free IPv4 and IPv6 Patricia tries in memory;
3. connects to `ris-live.ripe.net`;
4. receives BGP prefix updates;
5. updates the in-memory database;
6. serves live IP lookups on TCP port 43;
7. periodically checkpoints the current database back to the RAW file.

IPv4 prefixes are currently accepted from `/8` through `/24`.
IPv6 prefixes are currently accepted from `/16` through `/48`.

### Start

`bgp3` requires exactly one argument: the absolute path of the RAW database.

```sh
./bgp3 /absolute/path/bgp.raw
```

Example:

```sh
./bgp3 /home/www/fulltable/bgp.raw
```

If the RAW file exists, it is loaded before live updates begin.

If the RAW file does not exist, `bgp3` starts with an empty database and gradually learns prefixes from RIS Live updates. RIS Live is an update stream, so starting without a populated RAW file does not immediately provide a complete Internet routing table.

For normal operation it is therefore preferable to start from a previously saved RAW snapshot.

### Run in background

Example:

```sh
nohup ./bgp3 /home/www/fulltable/bgp.raw >bgp3.log 2>&1 &
```

### Live WHOIS queries

IPv4:

```sh
whois -h 127.0.0.1 8.8.8.8
```

IPv6:

```sh
whois -h 127.0.0.1 2001:4860:4860::8888
```

A lookup returns every matching stored prefix, from the most specific to the least specific.

Each match is printed as:

```text
CIDR ASN YYYYMMDDhhmmss
```

Example:

```text
24 13335 20260819091522
20 64500 20260819091203
--
2 match found
...
```

### Runtime statistics

Both `stat` and strings beginning with `stat` such as the historical `stats` watchdog query are accepted:

```sh
whois -h 127.0.0.1 stats
```

Important fields include:

```text
Tstart       process start time
Trx          time of the most recent RIS receive activity
Tnew         time the most recent new prefix was inserted
Nrestart     websocket reconnect count
Tsave        time of the most recent successful RAW checkpoint
Nsave        successful checkpoint count since process start
Nsave_error  failed checkpoint count
Nelm v4      stored IPv4 route count
Nnode v4     IPv4 Patricia node count
Nrx v4       received IPv4 update count
Nnew v4      new IPv4 prefixes inserted since process start
Nelm v6      stored IPv6 route count
Nnode v6     IPv6 Patricia node count
Nrx v6       received IPv6 update count
Nnew v6      new IPv6 prefixes inserted since process start
trie used    memory occupied by currently used Patricia nodes
trie capacity allocated Patricia storage including growth reserve
```

`Trx` intentionally remains the second output line because the historical watchdog uses that position to detect stale RIS activity.

There is no collision counter in `bgp3`: Patricia tries do not use hashing and therefore hash collisions do not exist.

### Checkpoints

An automatic checkpoint is performed every 15 minutes.

A manual checkpoint can be requested with signal 36:

```sh
killall -36 bgp3
```

The signal handler only sets a flag. A dedicated saver thread takes a compact in-memory snapshot and writes it to disk.

The final RAW file is not overwritten directly. The checkpoint is first written as:

```text
<raw path>.tmp
```

and then atomically renamed over the previous RAW file. This avoids leaving a partially written main snapshot after a normal write failure or interruption before the rename.

### Stop and restart

A practical restart sequence is:

```sh
killall -36 bgp3; sleep 2; killall -37 bgp3; while pgrep -x bgp3 >/dev/null; do sleep 1; done; nohup ./bgp3 /home/www/fulltable/bgp.raw >bgp3.log 2>&1 &
```

This performs:

1. explicit checkpoint request;
2. short time for the saver thread to complete;
3. graceful shutdown request using signal 37;
4. wait until the old process exits;
5. restart from the saved RAW snapshot.

For a simple stop:

```sh
killall -37 bgp3
```

### Historical watchdog compatibility

A watchdog can continue to use:

```sh
whois -h 127.0.0.1 stats
```

and inspect the second line (`Trx`).

The historical behaviour of requesting a checkpoint before killing an unhealthy process remains available:

```sh
killall -36 bgp3
sleep 5
killall -9 bgp3
```

The automatic 15-minute checkpoints reduce the amount of unsaved data at risk even if an emergency `SIGKILL` is eventually required.

## RAW database

### Role

`bgp.raw` is the persistent archive and should be treated as the primary data asset of IPAS.

The runtime Patricia trees are disposable indexes. If `bgp3` is restarted, they are reconstructed from `bgp.raw`.

Historical RAW snapshots can therefore be saved independently for future analysis.

### Current binary layout

The file starts with two 32-bit counters:

```text
uint32_t number_of_ipv4_records
uint32_t number_of_ipv6_records
```

They are followed by all IPv4 records and then all IPv6 records.

Current in-memory/disk structures are:

```c
struct v4disk {
  uint32_t ip;
  uint8_t cidr;
  uint32_t asn;
  uint32_t ts;
};

struct v6disk {
  uint64_t ip;
  uint8_t cidr;
  uint32_t asn;
  uint32_t ts;
};
```

On the current 64-bit Linux ABI these are 16 and 24 bytes respectively.

Important: the RAW format currently writes native C structures directly. It therefore depends on the ABI layout and native byte order of the machine that created it. Treat RAW snapshots as native-format files and do not assume binary portability to a machine with different endianness, integer layout or structure padding. A future portable RAW format can be introduced separately if cross-platform archival portability becomes necessary.

`ipas.cgi` validates the file size against the header counts before using a snapshot.

## ipas.cgi

### Purpose

`ipas.cgi` replaces the old `index.php`, `list.c` and `analyze.c` tools.

It reads only a completed RAW snapshot from disk and provides:

- IPv4 and IPv6 prefix totals;
- RAW size and snapshot modification time;
- CIDR distribution charts for IPv4 and IPv6;
- route freshness distribution;
- offline IPv4/IPv6 address lookup;
- ASN analysis;
- unique IPv4 address-space calculation per ASN with overlaps removed;
- IPv6 space expressed as unique `/48` equivalents with overlaps removed;
- clean IPv4 text export;
- clean IPv6 text export;
- sticky page header/navigation while scrolling;
- Top 10 AS by announced IPv4 address space and IPv6 `/48` equivalents, computed during the normal summary scan.

It does not connect to RIS Live and does not communicate with the running `bgp3` process.

### RAW path

For CGI operation the RAW path can be supplied through the environment:

```sh
IPAS_RAW=/absolute/path/bgp.raw
```

If `IPAS_RAW` is not set, the default is:

```text
/home/www/fulltable/bgp.raw
```

For command-line testing, an explicit path can also be supplied as the first argument.

### Local CGI tests

Summary page:

```sh
IPAS_RAW=$PWD/bgp.raw QUERY_STRING='' ./ipas.cgi
```

IPv4/IPv6 lookup:

```sh
IPAS_RAW=$PWD/bgp.raw QUERY_STRING='action=query&ip=8.8.8.8' ./ipas.cgi
```

ASN analysis:

```sh
IPAS_RAW=$PWD/bgp.raw QUERY_STRING='action=asn&asn=13335' ./ipas.cgi
```

### CGI actions / URLs

Summary:

```text
/ipas.cgi
/ipas.cgi?action=summary
```

IP lookup:

```text
/ipas.cgi?action=query&ip=8.8.8.8
/ipas.cgi?action=query&ip=2001:4860:4860::8888
```

ASN analysis:

```text
/ipas.cgi?action=asn&asn=13335
```

IPv4 export:

```text
/ipas.cgi?action=export4
```

IPv6 export:

```text
/ipas.cgi?action=export6
```

The export responses are plain text downloads with no statistics or header comments. Each row is:

```text
prefix/cidr,asn
```

Example:

```text
1.1.1.0/24,13335
```

### Web server setup

The web server must:

- be configured to execute `ipas.cgi` as CGI;
- have execute permission on `ipas.cgi`;
- have read permission on the selected RAW file and all parent directories;
- receive `IPAS_RAW` in its CGI environment if the RAW file is not at the default path.

No PHP runtime is required.

Because `ipas.cgi` is stateless, no second daemon, PID file or restart procedure is required.

## Runtime files and Git

The following are generated/runtime files and are ignored by Git:

```text
bgp3
ipas.cgi
bgp.raw
bgp.raw.tmp
*.log
```

The repository should contain source code, documentation and build files, not collected routing data or compiled binaries.

## Files in the project

```text
bgp3.c      live collector, Patricia indexes, WHOIS service and RAW checkpoints
ipas.c      stateless CGI RAW browser/analyzer/exporter
Makefile    build rules
README.md   project and operational documentation
.gitignore  runtime/build exclusions
```

## Operational principle

The intended long-term rule is simple:

```text
RAW snapshots are permanent data.
Everything else is replaceable and regenerable.
```

This allows old `bgp.raw` files to be retained for future routing-table analysis even if the runtime indexing or web frontend is redesigned later.
