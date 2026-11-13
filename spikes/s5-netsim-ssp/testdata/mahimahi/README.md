# Mahimahi traces (not committed)

Run `./fetch.sh` to download them into this directory.

* Source: https://github.com/ravinet/mahimahi/tree/master/traces, pinned
  to commit `f1346c38c415abfc98626dd82450f49a57033603` (2025-02-13).
* Recorded with the Saturator tool for Sprout: K. Winstein, A. Sivaraman,
  H. Balakrishnan, "Stochastic Forecasts Achieve High Throughput and Low
  Delay over Cellular Networks", USENIX NSDI 2013.
* Format: one millisecond timestamp per line, each an opportunity to
  deliver one 1500-byte packet (from the traces' README).
* **Licence: the Mahimahi repository is GPL-3.0** and the trace files carry
  no separate licence. Treat them as GPL-3.0 data. They are fetched at test
  time and git-ignored so that nothing GPL lands in this Apache-2.0 repo.
  Whether that is acceptable for CI fixtures is a question for Dan
  (FINDINGS.md, decisions).
