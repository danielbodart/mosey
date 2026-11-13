| layout | roaming | real client got post-relabel output (of 10) | datagrams to victim | bytes to victim | replayed command ran |
|---|---|---|---|---|---|
| B2 | trust | 0 | 25 | 1049 | 1x |
| B2 | validate | 10 | 6 | 252 | 1x |
| B | trust | 10 | 0 | 0 | 1x |
| B | validate | 10 | 0 | 0 | 1x |
<!-- B2/trust: RELABEL replayed first packet -->
<!-- B2/trust: RELABEL starting: 127.0.0.1:46893 -> 127.0.0.1:45391 -->
<!-- B2/trust: MOSEY-SPIKE STATS roam=trust peer=127.0.0.1:45391 challenges=0 switches=2 ratelimited=0 emu-replies ok=0 denied=0 net-starts=1 -->
<!-- B2/trust: CHILD-EXIT role=emu pid=332891 status=signal: killed -->
<!-- B2/trust: CHILD-EXIT role=net pid=332890 status=signal: killed lived=4.519s -->
<!-- B2/validate: RELABEL replayed first packet -->
<!-- B2/validate: RELABEL starting: 127.0.0.1:53087 -> 127.0.0.1:52214 -->
<!-- B2/validate: MOSEY-SPIKE STATS roam=validate peer=127.0.0.1:53087 challenges=7 switches=1 ratelimited=5 emu-replies ok=0 denied=0 net-starts=1 -->
<!-- B2/validate: CHILD-EXIT role=emu pid=333581 status=signal: killed -->
<!-- B2/validate: CHILD-EXIT role=net pid=333580 status=signal: killed lived=4.546s -->
<!-- B/trust: RELABEL replayed first packet -->
<!-- B/trust: RELABEL starting: 127.0.0.1:44213 -> 127.0.0.1:59547 -->
<!-- B/trust: MOSEY-SPIKE STATS roam=trust peer=127.0.0.1:59547 challenges=0 switches=2 ratelimited=0 emu-replies ok=0 denied=0 net-starts=1 -->
<!-- B/trust: CHILD-EXIT role=net pid=334234 status=signal: killed lived=4.532s -->
<!-- B/trust: CHILD-EXIT role=emu pid=334235 status=signal: killed -->
<!-- B/validate: RELABEL replayed first packet -->
<!-- B/validate: RELABEL starting: 127.0.0.1:38846 -> 127.0.0.1:40035 -->
<!-- B/validate: MOSEY-SPIKE STATS roam=validate peer=127.0.0.1:40035 challenges=2 switches=2 ratelimited=0 emu-replies ok=0 denied=0 net-starts=1 -->
<!-- B/validate: CHILD-EXIT role=emu pid=334802 status=signal: killed -->
<!-- B/validate: CHILD-EXIT role=net pid=334801 status=signal: killed lived=4.532s -->
