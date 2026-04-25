# openHiTLS Compatibility Validation Plan

Context:
- Goal: evolve `src/openssl_scanner/data/hitls_compat.json` into a per-interface truth library.
- Constraint: source-backed conclusions only. No speculative filling.
- Boundary: scanner core keeps generic HiTLS compatibility semantics; no HM-specific classification enters the truth library.

Current state:
- Inventory refreshed on 2026-04-25:
  - total mapped interfaces: `7206`
  - interfaces with `analysis_doc`: `7206`
  - interfaces still lacking `analysis_doc`: `0`
  - latest coverage: `{'not_available': 5438, 'partial': 1532, 'available': 236}`
  - current report-side missing-entry inventory against the latest `oh-source` full scan:
    - `0` missing unique symbols
    - `0` missing call-sites
    - report-side `unknown` backlog is fully backfilled into `hitls_compat.json`
- Batch 001 completed:
  - `SSL_CTX_new`
  - `SSL_read`
  - `SSL_write`
  - `BIO_free`
  - `BIO_new_file`
  - `EVP_EncodeBlock`
  - `EVP_DigestInit_ex`
  - `EVP_DigestUpdate`
  - `EVP_DigestFinal_ex`
  - `SHA256_Init`
  - `SHA256_Update`
  - `SHA256_Final`
- Validation doc: [hitls_compat_validation_batch_001.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_001.md)
- Batch 002 completed:
  - validation doc: [hitls_compat_validation_batch_002.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_002.md)
- Batch 003 completed:
  - validation doc: [hitls_compat_validation_batch_003.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_003.md)
- Batch 004 completed:
  - validation doc: [hitls_compat_validation_batch_004.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_004.md)
- Batch 005 completed:
  - validation doc: [hitls_compat_validation_batch_005.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_005.md)
- Batch 006 completed:
  - validation doc: [hitls_compat_validation_batch_006.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_006.md)
- Batch 007 completed:
  - validation doc: [hitls_compat_validation_batch_007.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_007.md)
- Batch 008 completed:
  - validation doc: [hitls_compat_validation_batch_008.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_008.md)
- Batch 009 completed:
  - validation doc: [hitls_compat_validation_batch_009.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_009.md)
- Batch 010 completed:
  - validation doc: [hitls_compat_validation_batch_010.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_010.md)
- Batch 011 completed:
  - validation doc: [hitls_compat_validation_batch_011.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_011.md)
- Batch 012 completed:
  - validation doc: [hitls_compat_validation_batch_012.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_012.md)
- Batch 013 completed:
  - validation doc: [hitls_compat_validation_batch_013.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_013.md)
- Batch 014 completed:
  - validation doc: [hitls_compat_validation_batch_014.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_014.md)
- Batch 015 completed:
  - validation doc: [hitls_compat_validation_batch_015.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_015.md)
- Batch 016 completed:
  - validation doc: [hitls_compat_validation_batch_016.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_016.md)
- Batch 017 completed:
  - validation doc: [hitls_compat_validation_batch_017.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_017.md)
- Batch 018 completed:
  - validation doc: [hitls_compat_validation_batch_018.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_018.md)
- Batch 019 completed:
  - validation doc: [hitls_compat_validation_batch_019.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_019.md)
- Batch 020 completed:
  - validation doc: [hitls_compat_validation_batch_020.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_020.md)
- Batch 021 completed:
  - validation doc: [hitls_compat_validation_batch_021.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_021.md)
- Batch 022 completed:
  - validation doc: [hitls_compat_validation_batch_022.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_022.md)
- Batch 023 completed:
  - validation doc: [hitls_compat_validation_batch_023.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_023.md)
- Batch 024 completed:
  - validation doc: [hitls_compat_validation_batch_024.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_024.md)
- Batch 025 completed:
  - validation doc: [hitls_compat_validation_batch_025.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_025.md)
- Batch 026 completed:
  - validation doc: [hitls_compat_validation_batch_026.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_026.md)
- Batch 027 completed:
  - validation doc: [hitls_compat_validation_batch_027.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_027.md)
- Batch 028 completed:
  - validation doc: [hitls_compat_validation_batch_028.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_028.md)
- Batch 029 completed:
  - validation doc: [hitls_compat_validation_batch_029.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_029.md)
- Batch 030 completed:
  - validation doc: [hitls_compat_validation_batch_030.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_030.md)
- Batch 031 completed:
  - validation doc: [hitls_compat_validation_batch_031.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_031.md)
- Batch 032 completed:
  - validation doc: [hitls_compat_validation_batch_032.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_032.md)
- Batch 033 completed:
  - validation doc: [hitls_compat_validation_batch_033.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_033.md)
- Batch 034 completed:
  - validation doc: [hitls_compat_validation_batch_034.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_034.md)
- Batch 035 completed:
  - validation doc: [hitls_compat_validation_batch_035.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_035.md)
- Batch 036 completed:
  - validation doc: [hitls_compat_validation_batch_036.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_036.md)
- Batch 037 completed:
  - validation doc: [hitls_compat_validation_batch_037.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_037.md)
- Batch 038 completed:
  - validation doc: [hitls_compat_validation_batch_038.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_038.md)
- Batch 039 completed:
  - validation doc: [hitls_compat_validation_batch_039.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_039.md)
- Batch 040 completed:
  - validation doc: [hitls_compat_validation_batch_040.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_040.md)
- Batch 041 completed:
  - validation doc: [hitls_compat_validation_batch_041.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_041.md)
- Batch 042 completed:
  - validation doc: [hitls_compat_validation_batch_042.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_042.md)
- Batch 043 completed:
  - validation doc: [hitls_compat_validation_batch_043.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_043.md)
- Batch 044 completed:
  - validation doc: [hitls_compat_validation_batch_044.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_044.md)
- Batch 045 completed:
  - validation doc: [hitls_compat_validation_batch_045.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_045.md)
- Batch 046 completed:
  - validation doc: [hitls_compat_validation_batch_046.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_046.md)
- Batch 047 completed:
  - validation doc: [hitls_compat_validation_batch_047.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_047.md)
- Batch 048 completed:
  - validation doc: [hitls_compat_validation_batch_048.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_048.md)
- Batch 049 completed:
  - validation doc: [hitls_compat_validation_batch_049.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_049.md)
- Batch 050 completed:
  - validation doc: [hitls_compat_validation_batch_050.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_050.md)
- Batch 051 completed:
  - validation doc: [hitls_compat_validation_batch_051.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_051.md)
- Batch 052 completed:
  - validation doc: [hitls_compat_validation_batch_052.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_052.md)
- Batch 053 completed:
  - validation doc: [hitls_compat_validation_batch_053.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_053.md)
- Batch 054 completed:
  - validation doc: [hitls_compat_validation_batch_054.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_054.md)
- Batch 055 completed:
  - validation doc: [hitls_compat_validation_batch_055.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_055.md)
- Batch 056 completed:
  - validation doc: [hitls_compat_validation_batch_056.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_056.md)
- Batch 057 completed:
  - validation doc: [hitls_compat_validation_batch_057.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_057.md)
- Batch 058 completed:
  - validation doc: [hitls_compat_validation_batch_058.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_058.md)
- Batch 059 completed:
  - validation doc: [hitls_compat_validation_batch_059.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_059.md)
- Batch 060 completed:
  - validation doc: [hitls_compat_validation_batch_060.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_060.md)
- Batch 061 completed:
  - validation doc: [hitls_compat_validation_batch_061.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_061.md)
- Batch 062 completed:
  - validation doc: [hitls_compat_validation_batch_062.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_062.md)
- Batch 063 completed:
  - validation doc: [hitls_compat_validation_batch_063.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_063.md)
- Batch 064 completed:
  - validation doc: [hitls_compat_validation_batch_064.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_064.md)
- Batch 065 completed:
  - validation doc: [hitls_compat_validation_batch_065.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_065.md)
- Batch 066 completed:
  - validation doc: [hitls_compat_validation_batch_066.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_066.md)
- Batch 067 completed:
  - validation doc: [hitls_compat_validation_batch_067.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_067.md)
- Batch 068 completed:
  - validation doc: [hitls_compat_validation_batch_068.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_068.md)
- Batch 069 completed:
  - validation doc: [hitls_compat_validation_batch_069.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_069.md)
- Batch 070 completed:
  - validation doc: [hitls_compat_validation_batch_070.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_070.md)
- Batch 071 completed:
  - validation doc: [hitls_compat_validation_batch_071.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_071.md)
- Batch 072 completed:
  - validation doc: [hitls_compat_validation_batch_072.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_072.md)
- Batch 073 completed:
  - validation doc: [hitls_compat_validation_batch_073.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_073.md)
- Batch 074 completed:
  - validation doc: [hitls_compat_validation_batch_074.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_074.md)
- Batch 075 completed:
  - validation doc: [hitls_compat_validation_batch_075.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_075.md)
- Batch 076 completed:
  - validation doc: [hitls_compat_validation_batch_076.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_076.md)
- Batch 077 completed:
  - validation doc: [hitls_compat_validation_batch_077.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_077.md)
- Batch 078 completed:
  - validation doc: [hitls_compat_validation_batch_078.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_078.md)
- Batch 079 completed:
  - validation doc: [hitls_compat_validation_batch_079.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_079.md)
- Batch 080 completed:
  - validation doc: [hitls_compat_validation_batch_080.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_080.md)
- Batch 081 completed:
  - validation doc: [hitls_compat_validation_batch_081.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_081.md)
- Batch 082 completed:
  - validation doc: [hitls_compat_validation_batch_082.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_082.md)
- Batch 083 completed:
  - validation doc: [hitls_compat_validation_batch_083.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_083.md)
- Batch 084 completed:
  - validation doc: [hitls_compat_validation_batch_084.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_084.md)
- Batch 085 completed:
  - validation doc: [hitls_compat_validation_batch_085.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_085.md)
- Batch 086 completed:
  - validation doc: [hitls_compat_validation_batch_086.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_086.md)
- Batch 087 completed:
  - validation doc: [hitls_compat_validation_batch_087.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_087.md)
- Batch 088 completed:
  - validation doc: [hitls_compat_validation_batch_088.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_088.md)
- Batch 089 completed:
  - validation doc: [hitls_compat_validation_batch_089.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_089.md)
- Batch 090 completed:
  - validation doc: [hitls_compat_validation_batch_090.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_090.md)
- Batch 091 completed:
  - validation doc: [hitls_compat_validation_batch_091.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_091.md)
- Batch 092 completed:
  - validation doc: [hitls_compat_validation_batch_092.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_092.md)
- Batch 093 completed:
  - validation doc: [hitls_compat_validation_batch_093.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_093.md)
- Batch 094 completed:
  - validation doc: [hitls_compat_validation_batch_094.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_094.md)
- Batch 095 completed:
  - validation doc: [hitls_compat_validation_batch_095.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_095.md)
- Batch 096 completed:
  - validation doc: [hitls_compat_validation_batch_096.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_096.md)
- Batch 097 completed:
  - validation doc: [hitls_compat_validation_batch_097.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_097.md)
- Batch 098 completed:
  - validation doc: [hitls_compat_validation_batch_098.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_098.md)
- Batch 099 completed:
  - validation doc: [hitls_compat_validation_batch_099.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_099.md)
- Batch 100 completed:
  - validation doc: [hitls_compat_validation_batch_100.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_100.md)
- Batch 101 completed:
  - validation doc: [hitls_compat_validation_batch_101.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_101.md)
- Batch 102 completed:
  - validation doc: [hitls_compat_validation_batch_102.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_102.md)
- Batch 103 completed:
  - validation doc: [hitls_compat_validation_batch_103.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_103.md)
- Batch 104 completed:
  - validation doc: [hitls_compat_validation_batch_104.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_104.md)
- Batch 105 completed:
  - validation doc: [hitls_compat_validation_batch_105.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_105.md)
- Batch 106 completed:
  - validation doc: [hitls_compat_validation_batch_106.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_106.md)
- Batch 107 completed:
  - validation doc: [hitls_compat_validation_batch_107.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_107.md)
- Batch 108 completed:
  - validation doc: [hitls_compat_validation_batch_108.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_108.md)
- Batch 109 completed:
  - validation doc: [hitls_compat_validation_batch_109.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_109.md)
- Batch 110 completed:
  - validation doc: [hitls_compat_validation_batch_110.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_110.md)
- Batch 111 completed:
  - validation doc: [hitls_compat_validation_batch_111.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_111.md)
- Batch 112 completed:
  - validation doc: [hitls_compat_validation_batch_112.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_112.md)
- Batch 113 completed:
  - validation doc: [hitls_compat_validation_batch_113.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_113.md)
- Batch 114 completed:
  - validation doc: [hitls_compat_validation_batch_114.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_114.md)
- Batch 115 completed:
  - validation doc: [hitls_compat_validation_batch_115.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_115.md)
- Batch 116 completed:
  - validation doc: [hitls_compat_validation_batch_116.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_116.md)
- Batch 117 completed:
  - validation doc: [hitls_compat_validation_batch_117.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_117.md)
- Batch 118 completed:
  - validation doc: [hitls_compat_validation_batch_118.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_118.md)
- Batch 119 completed:
  - validation doc: [hitls_compat_validation_batch_119.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_119.md)
- Batch 120 completed:
  - validation doc: [hitls_compat_validation_batch_120.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_120.md)
- Batch 121 completed:
  - validation doc: [hitls_compat_validation_batch_121.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_121.md)
- Batch 122 completed:
  - validation doc: [hitls_compat_validation_batch_122.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_122.md)
- Batch 123 completed:
  - validation doc: [hitls_compat_validation_batch_123.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_123.md)
- Batch 124 completed:
  - validation doc: [hitls_compat_validation_batch_124.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_124.md)
- Batch 125 completed:
  - validation doc: [hitls_compat_validation_batch_125.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_125.md)
- Batch 126 completed:
  - validation doc: [hitls_compat_validation_batch_126.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_126.md)
- Batch 127 completed:
  - validation doc: [hitls_compat_validation_batch_127.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_127.md)
- Batch 128 completed:
  - validation doc: [hitls_compat_validation_batch_128.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_128.md)
- Batch 129 completed:
  - validation doc: [hitls_compat_validation_batch_129.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_129.md)
- Batch 130 completed:
  - validation doc: [hitls_compat_validation_batch_130.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_130.md)
- Batch 131 completed:
  - validation doc: [hitls_compat_validation_batch_131.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_131.md)
- Batch 132 completed:
  - validation doc: [hitls_compat_validation_batch_132.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_132.md)
- Batch 133 completed:
  - validation doc: [hitls_compat_validation_batch_133.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_133.md)
- Batch 134 completed:
  - validation doc: [hitls_compat_validation_batch_134.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_134.md)
- Batch 135 completed:
  - validation doc: [hitls_compat_validation_batch_135.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_135.md)
- Batch 136 completed:
  - validation doc: [hitls_compat_validation_batch_136.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_136.md)
- Batch 137 completed:
  - validation doc: [hitls_compat_validation_batch_137.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_137.md)
- Batch 138 completed:
  - validation doc: [hitls_compat_validation_batch_138.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_138.md)
- Batch 139 completed:
  - validation doc: [hitls_compat_validation_batch_139.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_139.md)
- Batch 141 completed:
  - validation doc: [hitls_compat_validation_batch_141.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_141.md)
- Batch 142 completed:
  - validation doc: [hitls_compat_validation_batch_142.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_142.md)
- Batch 143 completed:
  - validation doc: [hitls_compat_validation_batch_143.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_143.md)
- Batch 144 completed:
  - validation doc: [hitls_compat_validation_batch_144.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_144.md)
- Batch 145 completed:
  - validation doc: [hitls_compat_validation_batch_145.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_145.md)
- Batch 146 completed:
  - validation doc: [hitls_compat_validation_batch_146.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_146.md)
- Batch 147 completed:
  - validation doc: [hitls_compat_validation_batch_147.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_147.md)
- Batch 148 completed:
  - validation doc: [hitls_compat_validation_batch_148.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_148.md)
- Batch 149 completed:
  - validation doc: [hitls_compat_validation_batch_149.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_149.md)
- Batch 150 completed:
  - validation doc: [hitls_compat_validation_batch_150.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_150.md)
- Batch 151 completed:
  - validation doc: [hitls_compat_validation_batch_151.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_151.md)
- Batch 152 completed:
  - validation doc: [hitls_compat_validation_batch_152.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_152.md)
- Batch 153 completed:
  - validation doc: [hitls_compat_validation_batch_153.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_153.md)
- Batch 154 completed:
  - validation doc: [hitls_compat_validation_batch_154.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_154.md)
- Batch 155 completed:
  - validation doc: [hitls_compat_validation_batch_155.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_155.md)
- Batch 156 completed:
  - validation doc: [hitls_compat_validation_batch_156.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_156.md)
- Batch 157 completed:
  - validation doc: [hitls_compat_validation_batch_157.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_157.md)
- Batch 158 completed:
  - validation doc: [hitls_compat_validation_batch_158.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_158.md)
- Batch 159 completed:
  - validation doc: [hitls_compat_validation_batch_159.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_159.md)
- Batch 160 completed:
  - validation doc: [hitls_compat_validation_batch_160.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_160.md)
- Batch 161 completed:
  - validation doc: [hitls_compat_validation_batch_161.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_161.md)
- Batch 162 completed:
  - validation doc: [hitls_compat_validation_batch_162.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_162.md)
- Batch 163 completed:
  - validation doc: [hitls_compat_validation_batch_163.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_163.md)
- Batch 164 completed:
  - validation doc: [hitls_compat_validation_batch_164.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_164.md)
- Batch 165 completed:
  - validation doc: [hitls_compat_validation_batch_165.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_165.md)
- Batch 166 completed:
  - validation doc: [hitls_compat_validation_batch_166.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_166.md)
- Batch 167 completed:
  - validation doc: [hitls_compat_validation_batch_167.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_167.md)
- Batch 168 completed:
  - validation doc: [hitls_compat_validation_batch_168.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_168.md)
- Batch 169 completed:
  - validation doc: [hitls_compat_validation_batch_169.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_169.md)
- Batch 170 completed:
  - validation doc: [hitls_compat_validation_batch_170.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_170.md)
- Batch 171 completed:
  - validation doc: [hitls_compat_validation_batch_171.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_171.md)
- Batch 172 completed:
  - validation doc: [hitls_compat_validation_batch_172.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_172.md)
- Batch 173 completed:
  - validation doc: [hitls_compat_validation_batch_173.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_173.md)
- Batch 174 completed:
  - validation doc: [hitls_compat_validation_batch_174.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_174.md)
- Batch 175 completed:
  - validation doc: [hitls_compat_validation_batch_175.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_175.md)
- Batch 176 completed:
  - validation doc: [hitls_compat_validation_batch_176.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_176.md)
- Batch 177 completed:
  - validation doc: [hitls_compat_validation_batch_177.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_177.md)
- Batch 178 completed:
  - validation doc: [hitls_compat_validation_batch_178.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_178.md)
- Batch 179 completed:
  - validation doc: [hitls_compat_validation_batch_179.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_179.md)
- Batch 180 completed:
  - validation doc: [hitls_compat_validation_batch_180.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_180.md)
- Batch 181 completed:
  - validation doc: [hitls_compat_validation_batch_181.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_181.md)
- Batch 182 completed:
  - validation doc: [hitls_compat_validation_batch_182.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_182.md)
- Batch 183 completed:
  - validation doc: [hitls_compat_validation_batch_183.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_183.md)
- Batch 184 completed:
  - validation doc: [hitls_compat_validation_batch_184.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_184.md)
- Batch 185 completed:
  - validation doc: [hitls_compat_validation_batch_185.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_185.md)
- Batch 186 completed:
  - validation doc: [hitls_compat_validation_batch_186.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_186.md)
- Batch 187 completed:
  - validation doc: [hitls_compat_validation_batch_187.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_187.md)
- Batch 188 completed:
  - validation doc: [hitls_compat_validation_batch_188.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_188.md)
- Batch 189 completed:
  - validation doc: [hitls_compat_validation_batch_189.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_189.md)
- Batch 190 completed:
  - validation doc: [hitls_compat_validation_batch_190.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_190.md)
- Batch 191 completed:
  - validation doc: [hitls_compat_validation_batch_191.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_191.md)
- Batch 192 completed:
  - validation doc: [hitls_compat_validation_batch_192.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_192.md)
- Next execution target:
  - `hitls_compat_validation_batch_193.md`
  - focus: `SSL_CTX family`
- Batch 193 completed:
  - validation doc: [hitls_compat_validation_batch_193.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_193.md)
- Next execution target:
  - `hitls_compat_validation_batch_194.md`
  - focus: `SSL_get family`
- Batch 194 completed:
  - validation doc: [hitls_compat_validation_batch_194.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_194.md)
- Next execution target:
  - `hitls_compat_validation_batch_195.md`
  - focus: `SSL_set family`
- Batch 195 completed:
  - validation doc: [hitls_compat_validation_batch_195.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_195.md)
- Batch 196 completed:
  - validation doc: [hitls_compat_validation_batch_196.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_196.md)
- Next execution target:
  - `hitls_compat_validation_batch_197.md`
  - focus: `X509_CRL family`
- Batch 197 completed:
  - validation doc: [hitls_compat_validation_batch_197.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_197.md)
- Next execution target:
  - `hitls_compat_validation_batch_198.md`
  - focus: `X509_REVOKED family`
- Batch 198 completed:
  - validation doc: [hitls_compat_validation_batch_198.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_198.md)
- Next execution target:
  - `hitls_compat_validation_batch_199.md`
  - focus: `X509_REQ family`
- Batch 199 completed:
  - validation doc: [hitls_compat_validation_batch_199.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_199.md)
- Next execution target:
  - `hitls_compat_validation_batch_200.md`
  - focus: `X509_ACERT family`
- Batch 200 completed:
  - validation doc: [hitls_compat_validation_batch_200.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_200.md)
- Next execution target:
  - `hitls_compat_validation_batch_201.md`
  - focus: `CMS family`
- Batch 201 completed:
  - validation doc: [hitls_compat_validation_batch_201.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_201.md)
- Next execution target:
  - `hitls_compat_validation_batch_202.md`
  - focus: `d2i family`
- Batch 202 completed:
  - validation doc: [hitls_compat_validation_batch_202.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_202.md)
- Next execution target:
  - `hitls_compat_validation_batch_203.md`
  - focus: `remaining d2i typed ASN.1 family`
- Batch 203 completed:
  - validation doc: [hitls_compat_validation_batch_203.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_203.md)
- Next execution target:
  - `hitls_compat_validation_batch_204.md`
  - focus: `d2i remaining X509/PKCS7/OCSP/TS family`
- Batch 204 completed:
  - validation doc: [hitls_compat_validation_batch_204.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_204.md)
- Next execution target:
  - `hitls_compat_validation_batch_205.md`
  - focus: `remaining d2i long tail`
- Batch 205 completed:
  - validation doc: [hitls_compat_validation_batch_205.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_205.md)
- Next execution target:
  - `hitls_compat_validation_batch_206.md`
  - focus: `remaining d2i long tail: typed params and protocol objects`
- Batch 206 completed:
  - validation doc: [hitls_compat_validation_batch_206.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_206.md)
- Next execution target:
  - `hitls_compat_validation_batch_207.md`
  - focus: `remaining d2i long tail: extension/value typed objects`
- Batch 207 completed:
  - validation doc: [hitls_compat_validation_batch_207.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_207.md)
- Next execution target:
  - `hitls_compat_validation_batch_208.md`
  - focus: `remaining d2i long tail: params and protocol residue`
- Batch 208 completed:
  - validation doc: [hitls_compat_validation_batch_208.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_208.md)
- Next execution target:
  - `hitls_compat_validation_batch_209.md`
  - focus: `remaining d2i long tail: params, signatures, sessions`
- Batch 209 completed:
  - validation doc: [hitls_compat_validation_batch_209.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_209.md)
- Next execution target:
  - `hitls_compat_validation_batch_210.md`
  - focus: `remaining d2i long tail: DH/EC params and protocol misc`
- Batch 210 completed:
  - validation doc: [hitls_compat_validation_batch_210.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_210.md)
- Next execution target:
  - `hitls_compat_validation_batch_211.md`
  - focus: `remaining non-d2i long tail`
- Batch 211 completed:
  - validation doc: [hitls_compat_validation_batch_211.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_211.md)
- Next execution target:
  - `hitls_compat_validation_batch_212.md`
  - focus: `BIO_ADDR / BIO network helper family`
- Batch 212 completed:
  - validation doc: [hitls_compat_validation_batch_212.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_212.md)
- Next execution target:
  - `hitls_compat_validation_batch_213.md`
  - focus: `BIO method and chain helper family`
- Batch 213 completed:
  - validation doc: [hitls_compat_validation_batch_213.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_213.md)
- Next execution target:
  - `hitls_compat_validation_batch_214.md`
  - focus: `i2d family`
- Batch 214 completed:
  - validation doc: [hitls_compat_validation_batch_214.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_214.md)
- Next execution target:
  - `hitls_compat_validation_batch_215.md`
  - focus: `i2d typed wrapper residue`
- Batch 215 completed:
  - validation doc: [hitls_compat_validation_batch_215.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_215.md)
- Next execution target:
  - `hitls_compat_validation_batch_216.md`
  - focus: `remaining i2d long tail`
- Batch 216 completed:
  - validation doc: [hitls_compat_validation_batch_216.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_216.md)
- Next execution target:
  - `hitls_compat_validation_batch_217.md`
  - focus: `remaining i2d long tail`
- Batch 217 completed:
  - validation doc: [hitls_compat_validation_batch_217.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_217.md)
- Next execution target:
  - `hitls_compat_validation_batch_218.md`
  - focus: `remaining i2d long tail`
- Batch 218 completed:
  - validation doc: [hitls_compat_validation_batch_218.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_218.md)
- Next execution target:
  - `hitls_compat_validation_batch_219.md`
  - focus: `remaining i2d long tail`
- Batch 219 completed:
  - validation doc: [hitls_compat_validation_batch_219.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_219.md)
- Next execution target:
  - `hitls_compat_validation_batch_220.md`
  - focus: `remaining i2d long tail`
- Batch 220 completed:
  - validation doc: [hitls_compat_validation_batch_220.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_220.md)
- Next execution target:
  - `hitls_compat_validation_batch_221.md`
  - focus: `remaining i2d long tail`
- Batch 221 completed:
  - validation doc: [hitls_compat_validation_batch_221.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_221.md)
- Next execution target:
  - `hitls_compat_validation_batch_222.md`
  - focus: `remaining i2d long tail`
- Batch 222 completed:
  - validation doc: [hitls_compat_validation_batch_222.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_222.md)
- Next execution target:
  - `hitls_compat_validation_batch_223.md`
  - focus: `remaining i2d long tail`
- Batch 223 completed:
  - validation doc: [hitls_compat_validation_batch_223.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_223.md)
- Next execution target:
  - `hitls_compat_validation_batch_224.md`
  - focus: `remaining i2d long tail`
- Batch 224 completed:
  - validation doc: [hitls_compat_validation_batch_224.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_224.md)
- Next execution target:
  - `hitls_compat_validation_batch_225.md`
  - focus: `remaining i2d long tail`
- Batch 225 completed:
  - validation doc: [hitls_compat_validation_batch_225.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_225.md)
- Next execution target:
  - `hitls_compat_validation_batch_226.md`
  - focus: `remaining i2d long tail`
- Batch 226 completed:
  - validation doc: [hitls_compat_validation_batch_226.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_226.md)
- Next execution target:
  - `hitls_compat_validation_batch_227.md`
  - focus: `remaining i2d long tail`
- Batch 227 completed:
  - validation doc: [hitls_compat_validation_batch_227.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_227.md)
- Next execution target:
  - `hitls_compat_validation_batch_228.md`
  - focus: `remaining i2d long tail`
- Batch 228 completed:
  - validation doc: [hitls_compat_validation_batch_228.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_228.md)
- Next execution target:
  - `hitls_compat_validation_batch_229.md`
  - focus: `remaining i2d long tail`
- Batch 229 completed:
  - validation doc: [hitls_compat_validation_batch_229.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_229.md)
- Next execution target:
  - `hitls_compat_validation_batch_230.md`
  - focus: `remaining i2d long tail`
- Batch 230 completed:
  - validation doc: [hitls_compat_validation_batch_230.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_230.md)
- Next execution target:
  - `hitls_compat_validation_batch_231.md`
  - focus: `remaining i2d long tail`
- Batch 231 completed:
  - validation doc: [hitls_compat_validation_batch_231.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_231.md)
- Next execution target:
  - `hitls_compat_validation_batch_232.md`
  - focus: `remaining i2d long tail`
- Batch 232 completed:
  - validation doc: [hitls_compat_validation_batch_232.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_232.md)
- Next execution target:
  - `hitls_compat_validation_batch_233.md`
  - focus: `remaining i2d long tail`
- Batch 233 completed:
  - validation doc: [hitls_compat_validation_batch_233.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_233.md)
- Next execution target:
  - `hitls_compat_validation_batch_234.md`
  - focus: `remaining i2d long tail`
- Batch 234 completed:
  - validation doc: [hitls_compat_validation_batch_234.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_234.md)
- Next execution target:
  - `hitls_compat_validation_batch_235.md`
  - focus: `OCSP family`
- Batch 235 completed:
  - validation doc: [hitls_compat_validation_batch_235.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_235.md)
- Next execution target:
  - `hitls_compat_validation_batch_236.md`
  - focus: `TS family`
- Batch 236 completed:
  - validation doc: [hitls_compat_validation_batch_236.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_236.md)
- Next execution target:
  - `hitls_compat_validation_batch_237.md`
  - focus: `PKCS7 family`
- Batch 237 completed:
  - validation doc: [hitls_compat_validation_batch_237.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_237.md)
- Next execution target:
  - `hitls_compat_validation_batch_238.md`
  - focus: `X509 subobject wrappers`
- Batch 238 completed:
  - validation doc: [hitls_compat_validation_batch_238.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_238.md)
- Next execution target:
  - `hitls_compat_validation_batch_239.md`
  - focus: `X509 registry / policy / trust / object family`
- Batch 239 completed:
  - validation doc: [hitls_compat_validation_batch_239.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_239.md)
- Next execution target:
  - `hitls_compat_validation_batch_240.md`
  - focus: `X509 get/get0/set/check family`
- Batch 240 completed:
  - validation doc: [hitls_compat_validation_batch_240.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_240.md)
- Next execution target:
  - `hitls_compat_validation_batch_241.md`
  - focus: `remaining X509 misc wrappers`
- Batch 241 completed:
  - validation doc: [hitls_compat_validation_batch_241.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_241.md)
- Next execution target:
  - `hitls_compat_validation_batch_242.md`
  - focus: `unsupported EVP cipher factory family`
- Batch 242 completed:
  - validation doc: [hitls_compat_validation_batch_242.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_242.md)
- Next execution target:
  - `hitls_compat_validation_batch_243.md`
  - focus: `EVP symmetric cipher residual family`
- Batch 243 completed:
  - validation doc: [hitls_compat_validation_batch_243.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_243.md)
- Next execution target:
  - `hitls_compat_validation_batch_244.md`
  - focus: `remaining EVP modern/core family`
- Batch 244 completed:
  - validation doc: [hitls_compat_validation_batch_244.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_244.md)
- Next execution target:
  - `hitls_compat_validation_batch_245.md`
  - focus: `SSL family`
- Batch 245 completed:
  - validation doc: [hitls_compat_validation_batch_245.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_245.md)
- Next execution target:
  - `hitls_compat_validation_batch_246.md`
  - focus: `PKCS12 family`
- Batch 246 completed:
  - validation doc: [hitls_compat_validation_batch_246.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_246.md)
- Next execution target:
  - `hitls_compat_validation_batch_247.md`
  - focus: `CRYPTO family`
- Batch 247 completed:
  - validation doc: [hitls_compat_validation_batch_247.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_247.md)
- Next execution target:
  - `hitls_compat_validation_batch_248.md`
  - focus: `OSSL family`
- Batch 248 completed:
  - validation doc: [hitls_compat_validation_batch_248.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_248.md)
- Next execution target:
  - `hitls_compat_validation_batch_249.md`
  - focus: `RSA family`
- Batch 249 completed:
  - validation doc: [hitls_compat_validation_batch_249.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_249.md)
- Next execution target:
  - `hitls_compat_validation_batch_250.md`
  - focus: `legacy DH/DSA key families`
- Batch 250 completed:
  - validation doc: [hitls_compat_validation_batch_250.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_250.md)
- Next execution target:
  - `hitls_compat_validation_batch_251.md`
  - focus: `OPENSSL + UI utility families`
- Batch 251 completed:
  - validation doc: [hitls_compat_validation_batch_251.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_251.md)
- Next execution target:
  - `hitls_compat_validation_batch_252.md`
  - focus: `ERR + CONF + NCONF + OBJ utility families`
- Batch 252 completed:
  - validation doc: [hitls_compat_validation_batch_252.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_252.md)
- Next execution target:
  - `hitls_compat_validation_batch_253.md`
  - focus: `CT + CTLOG + SCT family`
- Batch 253 completed:
  - validation doc: [hitls_compat_validation_batch_253.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_253.md)
- Next execution target:
  - `hitls_compat_validation_batch_254.md`
  - focus: `PEM + PKCS5 + PKCS8 low-volume utility families`
- Batch 254 completed:
  - validation doc: [hitls_compat_validation_batch_254.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_254.md)
- Next execution target:
  - `hitls_compat_validation_batch_255.md`
  - focus: `ENGINE + RAND + COMP + DSO utility families`
- Batch 255 completed:
  - validation doc: [hitls_compat_validation_batch_255.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_255.md)
- Next execution target:
  - `hitls_compat_validation_batch_256.md`
  - focus: `X509v3 + ESS + NETSCAPE tails`
- Batch 256 completed:
  - validation doc: [hitls_compat_validation_batch_256.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_256.md)
- Next execution target:
  - `hitls_compat_validation_batch_257.md`
  - focus: `legacy crypto helper tails`
- Batch 257 completed:
  - validation doc: [hitls_compat_validation_batch_257.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_257.md)
- Next execution target:
  - `hitls_compat_validation_batch_258.md`
  - focus: `ASN.1/X509 wrapper tails`
- Batch 258 completed:
  - validation doc: [hitls_compat_validation_batch_258.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_258.md)
- Next execution target:
  - `hitls_compat_validation_batch_259.md`
  - focus: `SSL/DTLS runtime tails`
- Batch 259 completed:
  - validation doc: [hitls_compat_validation_batch_259.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_259.md)
- Batch 260 completed:
  - validation doc: [hitls_compat_validation_batch_260.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_260.md)
- Batch 261 completed:
  - validation doc: [hitls_compat_validation_batch_261.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_261.md)
- Frontier status:
  - all mapped interfaces carry `analysis_doc`
  - report-side unknown backfill is complete for the current `oh-source` full scan

## Report-side Unknown Backfill Roadmap

Goal:
- eliminate report-side `unknown` results for currently scanned `oh-source` consumers by adding source-backed compat entries for every currently unknown symbol or macro.

Execution rule:
- keep batching by shared OpenSSL surface and shared openHiTLS replacement boundary
- prefer 50+ interfaces per batch when one evidence model covers them cleanly
- macros are included when the scanner reports them as OpenSSL symbols and they materially affect report coverage

Completed backfill batches:
- Batch 262 completed:
  - validation doc: [hitls_compat_validation_batch_262.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_262.md)
- Batch 263 completed:
  - validation doc: [hitls_compat_validation_batch_263.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_263.md)
- Batch 264 completed:
  - validation doc: [hitls_compat_validation_batch_264.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_264.md)
  - focus: `SSL_* / SSL_CTX_* / SSL_SESSION_* / DTLS* / TLS1_* runtime helpers`
  - scope size: `136` unknown symbols
- Batch 265 completed:
  - validation doc: [hitls_compat_validation_batch_265.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_265.md)
  - focus: `EVP_*` legacy helpers, `BIO_*` convenience helpers, and adjacent utility/error tails
  - scope size: `139` unknown symbols
- Batch 266 completed:
  - validation doc: [hitls_compat_validation_batch_266.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_266.md)
  - focus: `X509_*` / `PKCS7_*` / `PKCS12_*` / `OCSP_*` misc tails and adjacent serialization helpers
  - scope size: `54` unknown symbols
- Batch 267 completed:
  - validation doc: [hitls_compat_validation_batch_267.md](oh/scanner/docs/hitls-compat/hitls_compat_validation_batch_267.md)
  - focus: `OSSL_*` provider/internal macros, dynamic-bind internals, and the remaining small utility tails
  - scope size: `44` unknown symbols

Planning assumptions:
- Priority should follow real observed call frequency, not alphabetical order.
- Within a batch, interfaces should share the same public API surface and semantic comparison dimensions.
- Same-type interfaces should be aggregated into 50+ interface batches when they share one evidence model and one replacement boundary.
- Judge from practical replaceability, not just abstract capability.
- `available`:
  - public openHiTLS APIs can directly map or be compositionally substituted by developers to realize the OpenSSL interface in a practical migration path.
- `partial`:
  - functionality is mostly present, but public replacement still has meaningful boundary gaps such as missing semantic knobs, duplicate-handling differences, lifecycle mismatches that break straightforward substitution, or subset-only coverage.
- `not_available`:
  - public openHiTLS APIs do not provide a practically replaceable path, even if some lower-level capability or internal building block exists.
- Public multi-call composition alone is not sufficient for `available` unless it remains realistically substitutable for developers.
- Interfaces that are likely to be "not_available" still deserve validation if they have high real usage, because they materially affect scanner coverage ratios.

## Prioritization Method

Order batches by:
- observed OpenSSL call volume in current scan results
- number of `missing` / weakly justified entries in `hitls_compat.json`
- semantic coupling (interfaces from the same OpenSSL family should be reviewed together)
- ability to settle many downstream scanner results with one batch

## Batch Roadmap

## Pending Interface Queue

### Completed - Batch 002
- `X509_new`
- `X509_free`
- `X509_dup`
- `PEM_read_bio_X509`
- `X509_REQ_new`
- `X509_REQ_free`
- `X509_get_subject_name`
- `X509_get_issuer_name`
- `X509_get_ext_d2i`
- `X509_verify_cert`
- `X509_STORE_add_cert`
- `X509_STORE_free`
- `X509_STORE_CTX_get_error`
- `OCSP_BASICRESP_free`
- `OCSP_RESPONSE_free`

### Completed - Batch 003
- `EVP_PKEY_new`
- `EVP_PKEY_free`
- `EVP_PKEY_CTX_new`
- `EVP_PKEY_CTX_free`
- `EVP_PKEY_CTX_new_id`
- `EVP_PKEY_derive_init`
- `EVP_PKEY_derive`
- `EVP_PKEY_CTX_set_hkdf_md`
- `EVP_PKEY_CTX_set1_hkdf_key`
- `EVP_PKEY_CTX_set1_hkdf_salt`
- `EVP_PKEY_CTX_add1_hkdf_info`
- `EVP_PKEY_CTX_hkdf_mode`
- `RSA_new`
- `RSA_free`
- `DH_free`
- `EC_KEY_free`
- `EC_POINT_new`
- `EC_GROUP_free`
- `EC_KEY_get0_group`

### Completed - Batch 004
- `ERR_get_error`
- `ERR_error_string`
- `ERR_clear_error`
- `ERR_reason_error_string`
- `ERR_GET_REASON`
- `ERR_GET_LIB`
- `ERR_peek_error`
- `ERR_peek_last_error`
- `ERR_error_string_n`
- `OPENSSL_free`
- `OBJ_obj2txt`

### Completed - Batch 005
- `BN_new`
- `BN_free`
- `BN_clear_free`
- `BN_bin2bn`
- `BN_bn2bin`
- `BN_num_bytes`
- `BN_set_word`
- `BN_CTX_new`
- `BN_CTX_free`

### Completed - Batch 006
- `BIO_new`
- `BIO_s_mem`
- `BIO_read`
- `BIO_write`
- `BIO_pending`
- `BIO_new_file`
- `BIO_new_mem_buf`
- `BIO_get_mem_data`
- `BIO_reset`
- `BIO_printf`
- `BIO_free_all`

### Completed - Batch 007
- `SSL_new`
- `SSL_free`
- `SSL_get_error`
- `SSL_CTX_free`
- `SSL_CTX_get_cert_store`
- `TLS_client_method`
- `SSL_set_options`
- `SSL_CTX_set_options`
- `SSL_CTX_get_ex_data`
- `SSL_CTX_set_ex_data`
- `SSL_get_verify_result`
- `SSL_CTX_clear_options`
- `SSL_get0_alpn_selected`
- `SSL_get_SSL_CTX`
- `SSL_get_current_cipher`
- `SSL_CTX_set_verify`
- `SSL_CTX_set_cert_cb`
- `SSL_CTX_sess_set_new_cb`
- `SSL_SESSION_get_id`

### Completed - Batch 008
- `EVP_CIPHER_CTX_new`
- `EVP_CIPHER_CTX_free`
- `EVP_CIPHER_CTX_ctrl`
- `EVP_CIPHER_CTX_set_padding`
- `EVP_EncryptInit_ex`
- `EVP_DecryptInit_ex`
- `EVP_MD_CTX_new`
- `EVP_MD_CTX_free`
- `EVP_sha256`
- `EVP_sha384`
- `EVP_sha512`

### Completed - Batch 009
- `sk_X509_num`
- `sk_X509_value`
- `sk_X509_pop_free`
- `sk_X509_push`
- `ASN1_SIMPLE`
- `ASN1_EXP_OPT`
- `ASN1_SEQUENCE_END`
- `ASN1_STRING_length`
- `ASN1_STRING_get0_data`
- `ASN1_TIME_print`
- `ASN1_STRING_data`

### Completed - Batch 010
- `SSL_CTX_set_cipher_list`
- `SSL_CTX_set_ciphersuites`
- `SSL_CTX_set_alpn_protos`
- `SSL_CTX_set_alpn_select_cb`
- `SSL_CTX_set_client_CA_list`
- `SSL_CTX_set_client_cert_cb`
- `SSL_CTX_set_cert_verify_callback`
- `SSL_CTX_set_default_read_buffer_len`
- `SSL_CTX_set_num_tickets`
- `SSL_CTX_set_verify_depth`

### Completed - Batch 011
- `SSL_set_verify`
- `SSL_set_verify_depth`
- `SSL_get_verify_mode`
- `SSL_get_verify_depth`
- `SSL_get1_session`
- `SSL_get_session`
- `SSL_set_session`
- `SSL_get_finished`
- `SSL_get_peer_finished`
- `SSL_state_string_long`

### Completed - Batch 012
- `SSL_version`
- `SSL_get_state`
- `SSL_state_string`
- `SSL_get_quiet_shutdown`
- `SSL_get_shutdown`
- `SSL_get_num_tickets`
- `SSL_get_options`
- `SSL_clear_options`
- `SSL_has_pending`
- `SSL_is_init_finished`

### Completed - Batch 013
- `SSL_get_client_random`
- `SSL_get_server_random`
- `SSL_get_servername`
- `SSL_get_servername_type`
- `SSL_get_security_callback`
- `SSL_set_security_callback`
- `SSL_get_security_level`
- `SSL_set_security_level`
- `SSL_get_info_callback`
- `SSL_CTX_set_info_callback`

### Completed - Batch 014
- `SSL_set_quiet_shutdown`
- `SSL_set_shutdown`
- `SSL_set_read_ahead`
- `SSL_get_read_ahead`
- `SSL_set_num_tickets`
- `SSL_get_rbio`
- `SSL_get_wbio`
- `SSL_set_rfd`
- `SSL_set_wfd`

### Completed - Batch 015
- `SSL_get_psk_identity`
- `SSL_get_psk_identity_hint`
- `SSL_set_psk_client_callback`
- `SSL_set_psk_server_callback`
- `SSL_set_psk_use_session_callback`
- `SSL_set_psk_find_session_callback`
- `SSL_use_psk_identity_hint`
- `SSL_set_session_ticket_ext`
- `SSL_set_session_ticket_ext_cb`

### Completed - Batch 016
- `SSL_use_certificate`
- `SSL_use_certificate_ASN1`
- `SSL_use_certificate_file`
- `SSL_use_certificate_chain_file`
- `SSL_use_PrivateKey`
- `SSL_use_PrivateKey_ASN1`
- `SSL_use_PrivateKey_file`
- `SSL_CTX_use_certificate`
- `SSL_CTX_use_certificate_file`
- `SSL_CTX_use_certificate_chain_file`

### Completed - Batch 017
- `SSL_get_certificate`
- `SSL_get_privatekey`
- `SSL_check_private_key`
- `SSL_CTX_check_private_key`
- `SSL_CTX_get0_certificate`
- `SSL_CTX_get0_privatekey`
- `SSL_get0_peer_certificate`
- `SSL_get1_peer_certificate`

### Completed - Batch 018
- `SSL_connect`
- `SSL_accept`
- `SSL_do_handshake`
- `SSL_read_ex`
- `SSL_write_ex`
- `SSL_shutdown`
- `SSL_pending`
- `SSL_peek`
- `SSL_want`

### Completed - Batch 019
- `SSL_CTX_get0_CA_list`
- `SSL_CTX_get_client_CA_list`
- `SSL_CTX_set0_CA_list`
- `SSL_CTX_set_client_CA_list`
- `SSL_get0_peer_CA_list`
- `SSL_get_peer_cert_chain`
- `SSL_get0_verified_chain`

### Completed - Batch 020
- `SSL_get_verify_callback`
- `SSL_CTX_get_verify_callback`
- `SSL_CTX_get_client_cert_cb`
- `SSL_CTX_sess_get_get_cb`
- `SSL_CTX_sess_get_new_cb`
- `SSL_CTX_sess_get_remove_cb`
- `SSL_CTX_sess_set_get_cb`
- `SSL_CTX_sess_set_remove_cb`

### Completed - Batch 021
- `SSL_CTX_get_info_callback`
- `SSL_CTX_get_num_tickets`
- `SSL_CTX_get_options`
- `SSL_CTX_get_quiet_shutdown`
- `SSL_CTX_get_security_callback`
- `SSL_CTX_get_security_level`
- `SSL_CTX_get_timeout`
- `SSL_CTX_get_verify_depth`
- `SSL_CTX_get_verify_mode`

### Completed - Batch 022
- `SSL_SESSION_free`
- `SSL_SESSION_dup`
- `SSL_SESSION_set1_id`
- `SSL_SESSION_get0_id_context`
- `SSL_SESSION_set1_id_context`
- `SSL_SESSION_get_timeout`
- `SSL_SESSION_set_timeout`
- `SSL_SESSION_get_protocol_version`
- `SSL_SESSION_set_protocol_version`

### Completed - Batch 023
- `SSL_SESSION_new`
- `SSL_SESSION_get0_cipher`
- `SSL_SESSION_set_cipher`
- `SSL_SESSION_get_ex_data`
- `SSL_SESSION_set_ex_data`
- `SSL_SESSION_has_ticket`
- `SSL_SESSION_is_resumable`
- `SSL_SESSION_get_master_key`
- `SSL_SESSION_set1_master_key`

### Completed - Batch 024
- `SSL_SESSION_get0_alpn_selected`
- `SSL_SESSION_set1_alpn_selected`
- `SSL_SESSION_get0_ticket`
- `SSL_SESSION_get_ticket_lifetime_hint`
- `SSL_SESSION_get_time`
- `SSL_SESSION_set_time`
- `SSL_SESSION_get0_peer`
- `SSL_SESSION_get0_hostname`
- `SSL_SESSION_set1_hostname`

### Completed - Batch 025
- `EVP_EncryptUpdate`
- `EVP_EncryptFinal_ex`
- `EVP_DecryptUpdate`
- `EVP_DecryptFinal_ex`
- `EVP_aes_128_gcm`
- `EVP_aes_256_gcm`
- `EVP_aes_128_cbc`
- `EVP_aes_128_ctr`
- `EVP_aes_256_cbc`

### Completed - Batch 026
- `RAND_bytes`
- `RAND_bytes_ex`
- `RAND_priv_bytes`
- `RAND_priv_bytes_ex`
- `RAND_seed`
- `RAND_add`
- `RAND_poll`
- `RAND_status`

### Completed - Batch 027
- `HMAC_CTX_new`
- `HMAC_CTX_free`
- `HMAC_Init_ex`
- `HMAC_Update`
- `HMAC_Final`
- `HMAC`

### Completed - Batch 028
- `PEM_read_bio_PrivateKey`
- `X509_get_pubkey`
- `X509_get_serialNumber`
- `d2i_X509`
- `d2i_X509_bio`
- `i2d_X509`
- `PEM_write_bio_X509`

### Completed - Batch 029
- `SHA256`
- `EVP_sha1`
- `EVP_md5`
- `EVP_Digest`
- `EVP_DigestInit`
- `EVP_DigestFinal`

### Completed - Batch 030
- `EVP_PKEY_set1_RSA`
- `RSA_set0_key`
- `EVP_PKEY_CTX_set_rsa_padding`
- `RSA_generate_key_ex`
- `RSA_size`

### Completed - Batch 031
- `SSL_set_bio`
- `SSL_set_fd`
- `BIO_set_flags`
- `BIO_s_file`

### Completed - Batch 032
- `SSL_CTX_load_verify_locations`
- `SSL_CTX_use_PrivateKey_file`
- `SSL_CTX_use_PrivateKey`
- `TLS_server_method`
- `SSL_set_connect_state`

### Completed - Batch 033
- `EVP_DigestSignInit`
- `EVP_DigestVerifyInit`
- `EVP_DigestSignFinal`
- `EVP_DigestSignUpdate`
- `EVP_DigestVerifyFinal`
- `EVP_PKEY_verify`
- `EVP_PKEY_verify_init`

### Completed - Batch 034
- `X509_verify_cert_error_string`
- `X509_NAME_oneline`
- `X509_verify`
- `X509_EXTENSION_get_data`
- `X509_NAME_ENTRY_get_data`
- `X509_NAME_get_entry`
- `X509_NAME_add_entry_by_txt`
- `X509_NAME_get_text_by_NID`

### Completed - Batch 035
- `OBJ_obj2nid`
- `OBJ_nid2sn`
- `OBJ_txt2obj`
- `EVP_get_digestbyname`

### Completed - Batch 036
- `EC_KEY_new_by_curve_name`
- `EC_GROUP_get_curve_name`
- `EC_KEY_generate_key`
- `EC_KEY_get0_private_key`
- `EC_KEY_get0_public_key`
- `EC_GROUP_new_by_curve_name`
- `EC_KEY_new`
- `EC_KEY_set_group`

### Completed - Batch 037
- `X509_STORE_new`
- `X509_STORE_CTX_get_ex_data`
- `X509_get0_notAfter`
- `X509_get0_notBefore`
- `X509_get0_pubkey`
- `X509_up_ref`
- `X509_CRL_verify`
- `X509_NAME_new`

### Completed - Batch 038
- `ASN1_STRING_to_UTF8`
- `ASN1_OCTET_STRING_new`
- `ASN1_STRING_set`
- `ASN1_INTEGER_set`
- `ASN1_OBJECT_free`
- `ASN1_OCTET_STRING_free`
- `ASN1_OCTET_STRING_set`
- `ASN1_TIME_to_tm`

### Completed - Batch 039
- `BN_bn2binpad`
- `BN_cmp`
- `BN_mod_exp`
- `BN_num_bits`

### Completed - Batch 040
- `BN_CTX_end`
- `BN_CTX_get`
- `BN_CTX_new_ex`
- `BN_CTX_secure_new`
- `BN_CTX_secure_new_ex`
- `BN_CTX_start`

### Completed - Batch 041
- `BN_GENCB_call`
- `BN_GENCB_free`
- `BN_GENCB_get_arg`
- `BN_GENCB_new`
- `BN_GENCB_set`
- `BN_GENCB_set_old`

### Completed - Batch 042
- `BN_BLINDING_new`
- `BN_BLINDING_free`
- `BN_BLINDING_update`
- `BN_BLINDING_convert`
- `BN_BLINDING_invert`
- `BN_BLINDING_set_flags`

### Completed - Batch 043
- `BN_BLINDING_convert_ex`
- `BN_BLINDING_invert_ex`
- `BN_BLINDING_create_param`
- `BN_BLINDING_get_flags`
- `BN_BLINDING_is_current_thread`
- `BN_BLINDING_set_current_thread`
- `BN_BLINDING_lock`
- `BN_BLINDING_unlock`

### Completed - Batch 044
- `BN_copy`
- `BN_dup`
- `BN_get_word`
- `BN_set_word`
- `BN_swap`
- `BN_with_flags`

### Completed - Batch 045
- `BN_get_flags`
- `BN_set_flags`
- `BN_is_negative`
- `BN_set_negative`
- `BN_is_zero`
- `BN_is_one`

### Completed - Batch 046
- `BN_rand`
- `BN_rand_ex`
- `BN_priv_rand`
- `BN_priv_rand_ex`
- `BN_rand_range`
- `BN_rand_range_ex`

### Completed - Batch 047
- `BN_bin2bn`
- `BN_lebin2bn`
- `BN_native2bn`
- `BN_hex2bn`
- `BN_dec2bn`
- `BN_mpi2bn`

### Completed - Batch 048
- `BN_bn2hex`
- `BN_bn2dec`
- `BN_bn2mpi`
- `BN_print`
- `BN_print_fp`
- `BN_bn2nativepad`

### Completed - Batch 049
- `BN_add`
- `BN_sub`
- `BN_add_word`
- `BN_sub_word`
- `BN_mul`
- `BN_mul_word`

### Completed - Batch 050
- `BN_lshift`
- `BN_lshift1`
- `BN_rshift`
- `BN_rshift1`
- `BN_set_bit`
- `BN_clear_bit`

### Completed - Batch 051
- `BN_MONT_CTX_new`
- `BN_MONT_CTX_free`
- `BN_MONT_CTX_set`
- `BN_MONT_CTX_copy`
- `BN_RECP_CTX_new`
- `BN_RECP_CTX_free`

### Completed - Batch 052
- `BN_mod_mul_montgomery`
- `BN_to_montgomery`
- `BN_from_montgomery`
- `BN_mod_exp_mont`
- `BN_mod_exp_mont_consttime`

### Completed - Batch 053
- `BN_MONT_CTX_set_locked`
- `BN_RECP_CTX_set`
- `BN_mod_exp_recp`
- `BN_mod_exp_mont_word`
- `BN_mod_exp2_mont`
- `BN_mod_exp_mont_consttime_x2`

### Completed - Batch 054
- `BN_div`
- `BN_div_word`
- `BN_mod`
- `BN_mod_word`
- `BN_nnmod`
- `BN_mod_mul_reciprocal`

### Completed - Batch 055
- `BN_generate_prime`
- `BN_generate_prime_ex`
- `BN_generate_prime_ex2`
- `BN_check_prime`
- `BN_is_prime`
- `BN_is_prime_ex`

### Completed - Batch 056
- `BN_GF2m_add`
- `BN_GF2m_mod`
- `BN_GF2m_mod_mul`
- `BN_GF2m_mod_sqr`
- `BN_GF2m_mod_inv`
- `BN_GF2m_mod_sqrt`

### Completed - Batch 057
- `BN_GF2m_mod_div`
- `BN_GF2m_mod_exp`
- `BN_GF2m_mod_solve_quad`
- `BN_GF2m_mod_arr`
- `BN_GF2m_mod_mul_arr`
- `BN_GF2m_mod_sqr_arr`

### Completed - Batch 058
- `BN_GF2m_mod_inv_arr`
- `BN_GF2m_mod_div_arr`
- `BN_GF2m_mod_exp_arr`
- `BN_GF2m_mod_sqrt_arr`
- `BN_GF2m_mod_solve_quad_arr`
- `BN_GF2m_poly2arr`
- `BN_GF2m_arr2poly`

### Completed - Batch 059
- `BN_X931_generate_prime_ex`
- `BN_X931_generate_Xpq`
- `BN_X931_derive_prime_ex`

### Completed - Batch 060
- `BN_get_rfc2409_prime_768`
- `BN_get_rfc2409_prime_1024`
- `BN_get_rfc3526_prime_1536`
- `BN_get_rfc3526_prime_2048`
- `BN_get_rfc3526_prime_3072`
- `BN_get_rfc3526_prime_4096`

### Completed - Batch 061
- `BN_get_rfc3526_prime_6144`
- `BN_get_rfc3526_prime_8192`
- `BN_get0_nist_prime_192`
- `BN_get0_nist_prime_224`
- `BN_get0_nist_prime_256`
- `BN_get0_nist_prime_384`

### Completed - Batch 062
- `BN_get0_nist_prime_521`
- `BN_value_one`
- `BN_options`
- `BN_security_bits`
- `BN_are_coprime`
- `BN_abs_is_word`

### Completed - Batch 063
- `BN_ucmp`
- `BN_is_word`
- `BN_is_odd`
- `BN_is_bit_set`
- `BN_consttime_swap`

### Completed - Batch 064
- `BN_mod_add`
- `BN_mod_add_quick`
- `BN_mod_sub`
- `BN_mod_sub_quick`
- `BN_mod_mul`
- `BN_mod_sqr`
- `BN_mod_inverse`
- `BN_mod_lshift`
- `BN_mod_lshift1`
- `BN_mod_lshift1_quick`
- `BN_mod_lshift_quick`

### Completed - Batch 065
- `BN_exp`
- `BN_sqr`
- `BN_gcd`
- `BN_div_recp`
- `BN_reciprocal`
- `BN_kronecker`
- `BN_uadd`
- `BN_usub`

### Completed - Batch 066
- `BN_generate_dsa_nonce`
- `BN_is_prime_fasttest`
- `BN_is_prime_fasttest_ex`
- `BN_priv_rand_range`
- `BN_priv_rand_range_ex`
- `BN_pseudo_rand`
- `BN_pseudo_rand_range`
- `BN_signed_bin2bn`
- `BN_signed_bn2bin`
- `BN_signed_bn2lebin`
- `BN_signed_bn2native`
- `BN_signed_lebin2bn`
- `BN_signed_native2bn`

### Completed - Batch 067
- `BN_asc2bn`
- `BN_bn2lebinpad`
- `BN_bntest_rand`
- `BN_clear`
- `BN_mod_sqrt`
- `BN_nist_mod_192`
- `BN_nist_mod_224`
- `BN_nist_mod_256`
- `BN_nist_mod_384`
- `BN_nist_mod_521`
- `BN_nist_mod_func`
- `BN_to_ASN1_ENUMERATED`
- `BN_to_ASN1_INTEGER`

### Completed - Batch 068
- `AES_set_encrypt_key`
- `AES_set_decrypt_key`
- `AES_encrypt`
- `AES_decrypt`
- `AES_ecb_encrypt`
- `AES_cbc_encrypt`

### Completed - Batch 069
- `DES_cbc_encrypt`
- `DES_ecb_encrypt`
- `DES_cfb64_encrypt`
- `DES_ofb_encrypt`
- `DES_set_key_unchecked`
- `DES_set_odd_parity`

### Completed - Batch 070
- `AES_cfb128_encrypt`
- `AES_cfb1_encrypt`
- `AES_cfb8_encrypt`
- `AES_ofb128_encrypt`
- `AES_wrap_key`
- `AES_unwrap_key`
- `AES_ige_encrypt`
- `AES_bi_ige_encrypt`
- `AES_options`

### Completed - Batch 071
- `DES_cbc_cksum`
- `DES_cfb_encrypt`
- `DES_check_key_parity`
- `DES_crypt`
- `DES_decrypt3`
- `DES_ecb3_encrypt`
- `DES_ede3_cbc_encrypt`
- `DES_ede3_cfb64_encrypt`
- `DES_ede3_cfb_encrypt`
- `DES_ede3_ofb64_encrypt`
- `DES_encrypt1`
- `DES_encrypt2`
- `DES_encrypt3`
- `DES_fcrypt`

### Completed - Batch 072
- `DES_is_weak_key`
- `DES_key_sched`
- `DES_ncbc_encrypt`
- `DES_ofb64_encrypt`
- `DES_options`
- `DES_pcbc_encrypt`
- `DES_quad_cksum`
- `DES_random_key`
- `DES_set_key`
- `DES_set_key_checked`
- `DES_string_to_2keys`
- `DES_string_to_key`
- `DES_xcbc_encrypt`

### Completed - Batch 073
- `BF_cbc_encrypt`
- `BF_cfb64_encrypt`
- `BF_decrypt`
- `BF_ecb_encrypt`
- `BF_encrypt`
- `BF_ofb64_encrypt`
- `BF_options`
- `BF_set_key`

### Completed - Batch 074
- `Camellia_cbc_encrypt`
- `Camellia_cfb128_encrypt`
- `Camellia_cfb1_encrypt`
- `Camellia_cfb8_encrypt`
- `Camellia_ctr128_encrypt`
- `Camellia_decrypt`
- `Camellia_ecb_encrypt`
- `Camellia_encrypt`
- `Camellia_ofb128_encrypt`
- `Camellia_set_key`

### Completed - Batch 075
- `IDEA_cbc_encrypt`
- `IDEA_cfb64_encrypt`
- `IDEA_ecb_encrypt`
- `IDEA_encrypt`
- `IDEA_ofb64_encrypt`
- `IDEA_options`
- `IDEA_set_decrypt_key`
- `IDEA_set_encrypt_key`

### Completed - Batch 076
- `RC2_cbc_encrypt`
- `RC2_cfb64_encrypt`
- `RC2_decrypt`
- `RC2_ecb_encrypt`
- `RC2_encrypt`
- `RC2_ofb64_encrypt`
- `RC2_set_key`

### Completed - Batch 077
- `SEED_cbc_encrypt`
- `SEED_cfb128_encrypt`
- `SEED_decrypt`
- `SEED_ecb_encrypt`
- `SEED_encrypt`
- `SEED_ofb128_encrypt`
- `SEED_set_key`

### Completed - Batch 078
- `CAST_cbc_encrypt`
- `CAST_cfb64_encrypt`
- `CAST_decrypt`
- `CAST_ecb_encrypt`
- `CAST_encrypt`
- `CAST_ofb64_encrypt`
- `CAST_set_key`

### Completed - Batch 079
- `ASN1_BIT_STRING_free`
- `ASN1_BIT_STRING_new`
- `ASN1_BIT_STRING_set`
- `ASN1_BIT_STRING_get_bit`
- `ASN1_BIT_STRING_set_bit`
- `ASN1_BIT_STRING_check`
- `ASN1_BIT_STRING_num_asc`
- `ASN1_BIT_STRING_set_asc`

### Completed - Batch 080
- `ASN1_BMPSTRING_free`
- `ASN1_BMPSTRING_it`
- `ASN1_BMPSTRING_new`
- `ASN1_BOOLEAN_it`
- `ASN1_ENUMERATED_free`
- `ASN1_ENUMERATED_get`
- `ASN1_ENUMERATED_get_int64`
- `ASN1_ENUMERATED_it`

### Completed - Batch 081
- `ASN1_ENUMERATED_new`
- `ASN1_ENUMERATED_set`
- `ASN1_ENUMERATED_set_int64`
- `ASN1_ENUMERATED_to_BN`
- `ASN1_FBOOLEAN_it`
- `ASN1_GENERALIZEDTIME_adj`
- `ASN1_GENERALIZEDTIME_check`
- `ASN1_GENERALIZEDTIME_dup`

### Completed - Batch 082
- `ASN1_GENERALIZEDTIME_free`
- `ASN1_GENERALIZEDTIME_it`
- `ASN1_GENERALIZEDTIME_new`
- `ASN1_GENERALIZEDTIME_print`
- `ASN1_GENERALIZEDTIME_set`
- `ASN1_GENERALIZEDTIME_set_string`
- `ASN1_GENERALSTRING_free`
- `ASN1_GENERALSTRING_it`

### Completed - Batch 083
- `ASN1_GENERALSTRING_new`
- `ASN1_IA5STRING_free`
- `ASN1_IA5STRING_it`
- `ASN1_IA5STRING_new`
- `ASN1_INTEGER_cmp`
- `ASN1_INTEGER_dup`
- `ASN1_INTEGER_free`
- `ASN1_INTEGER_get`

### Completed - Batch 084
- `ASN1_INTEGER_get_int64`
- `ASN1_INTEGER_get_uint64`
- `ASN1_INTEGER_it`
- `ASN1_INTEGER_new`
- `ASN1_INTEGER_set_int64`
- `ASN1_INTEGER_set_uint64`
- `ASN1_INTEGER_to_BN`
- `ASN1_NULL_free`

### Completed - Batch 085
- `ASN1_NULL_it`
- `ASN1_NULL_new`
- `ASN1_OBJECT_create`
- `ASN1_OBJECT_it`
- `ASN1_OBJECT_new`
- `ASN1_OCTET_STRING_NDEF_it`
- `ASN1_OCTET_STRING_cmp`
- `ASN1_OCTET_STRING_dup`

### Completed - Batch 086
- `ASN1_OCTET_STRING_it`
- `ASN1_PCTX_free`
- `ASN1_PCTX_get_cert_flags`
- `ASN1_PCTX_get_flags`
- `ASN1_PCTX_get_nm_flags`
- `ASN1_PCTX_get_oid_flags`
- `ASN1_PCTX_get_str_flags`
- `ASN1_PCTX_new`

### Completed - Batch 087
- `ASN1_PCTX_set_cert_flags`
- `ASN1_PCTX_set_flags`
- `ASN1_PCTX_set_nm_flags`
- `ASN1_PCTX_set_oid_flags`
- `ASN1_PCTX_set_str_flags`
- `ASN1_PRINTABLESTRING_free`
- `ASN1_PRINTABLESTRING_it`
- `ASN1_PRINTABLESTRING_new`

### Completed - Batch 088
- `ASN1_PRINTABLE_free`
- `ASN1_PRINTABLE_it`
- `ASN1_PRINTABLE_new`
- `ASN1_PRINTABLE_type`
- `ASN1_SCTX_free`
- `ASN1_SCTX_get_app_data`
- `ASN1_SCTX_get_flags`
- `ASN1_SCTX_get_item`
- `ASN1_SCTX_get_template`
- `ASN1_SCTX_new`
- `ASN1_SCTX_set_app_data`

### Completed - Batch 089
- `ASN1_SEQUENCE_ANY_it`
- `ASN1_SEQUENCE_it`
- `ASN1_SET_ANY_it`
- `ASN1_STRING_TABLE_add`
- `ASN1_STRING_TABLE_cleanup`
- `ASN1_STRING_TABLE_get`
- `ASN1_STRING_clear_free`
- `ASN1_STRING_cmp`

### Completed - Batch 090
- `ASN1_STRING_copy`
- `ASN1_STRING_dup`
- `ASN1_STRING_free`
- `ASN1_STRING_get_default_mask`
- `ASN1_STRING_length_set`
- `ASN1_STRING_new`
- `ASN1_STRING_print`
- `ASN1_STRING_print_ex`

### Completed - Batch 091
- `ASN1_STRING_print_ex_fp`
- `ASN1_STRING_set0`
- `ASN1_STRING_set_by_NID`
- `ASN1_STRING_set_default_mask`
- `ASN1_STRING_set_default_mask_asc`
- `ASN1_STRING_type`
- `ASN1_STRING_type_new`

### Completed - Batch 092
- `ASN1_T61STRING_free`
- `ASN1_T61STRING_it`
- `ASN1_T61STRING_new`
- `ASN1_TBOOLEAN_it`
- `ASN1_TIME_adj`
- `ASN1_TIME_check`
- `ASN1_TIME_cmp_time_t`
- `ASN1_TIME_compare`

### Completed - Batch 093
- `ASN1_TIME_diff`
- `ASN1_TIME_dup`
- `ASN1_TIME_free`
- `ASN1_TIME_it`
- `ASN1_TIME_new`
- `ASN1_TIME_normalize`
- `ASN1_TIME_print_ex`
- `ASN1_TIME_set`

### Completed - Batch 094
- `ASN1_TIME_set_string`
- `ASN1_TIME_set_string_X509`
- `ASN1_TIME_to_generalizedtime`
- `ASN1_UTCTIME_adj`
- `ASN1_UTCTIME_check`
- `ASN1_UTCTIME_cmp_time_t`
- `ASN1_UTCTIME_dup`
- `ASN1_UTCTIME_free`

### Completed - Batch 095
- `ASN1_UTCTIME_it`
- `ASN1_UTCTIME_new`
- `ASN1_UTCTIME_print`
- `ASN1_UTCTIME_set`
- `ASN1_UTCTIME_set_string`
- `ASN1_UTF8STRING_free`
- `ASN1_UTF8STRING_it`
- `ASN1_UTF8STRING_new`

### Completed - Batch 096
- `ASN1_UNIVERSALSTRING_free`
- `ASN1_UNIVERSALSTRING_it`
- `ASN1_UNIVERSALSTRING_new`
- `ASN1_UNIVERSALSTRING_to_string`
- `ASN1_VISIBLESTRING_free`
- `ASN1_VISIBLESTRING_it`
- `ASN1_VISIBLESTRING_new`

### Completed - Batch 097
- `ASN1_ANY_it`
- `ASN1_BIT_STRING_it`
- `ASN1_BIT_STRING_name_print`

### Completed - Batch 098
- `ASN1_TYPE_cmp`
- `ASN1_TYPE_free`
- `ASN1_TYPE_get`
- `ASN1_TYPE_get_int_octetstring`
- `ASN1_TYPE_get_octetstring`
- `ASN1_TYPE_new`
- `ASN1_TYPE_pack_sequence`
- `ASN1_TYPE_set`
- `ASN1_TYPE_set1`
- `ASN1_TYPE_set_int_octetstring`
- `ASN1_TYPE_set_octetstring`
- `ASN1_TYPE_unpack_sequence`

### Completed - Batch 099
- `ASN1_ITEM_get`
- `ASN1_ITEM_lookup`
- `ASN1_d2i_bio`
- `ASN1_i2d_bio`
- `ASN1_item_d2i`
- `ASN1_item_d2i_bio`
- `ASN1_item_d2i_bio_ex`
- `ASN1_item_d2i_ex`
- `ASN1_item_d2i_fp`
- `ASN1_item_d2i_fp_ex`
- `ASN1_item_digest`
- `ASN1_item_dup`
- `ASN1_item_ex_d2i`
- `ASN1_item_ex_free`
- `ASN1_item_ex_i2d`
- `ASN1_item_ex_new`
- `ASN1_item_free`
- `ASN1_item_i2d`
- `ASN1_item_i2d_bio`
- `ASN1_item_i2d_fp`
- `ASN1_item_i2d_mem_bio`
- `ASN1_item_ndef_i2d`
- `ASN1_item_new`
- `ASN1_item_new_ex`
- `ASN1_item_pack`
- `ASN1_item_print`
- `ASN1_item_sign`
- `ASN1_item_sign_ctx`
- `ASN1_item_sign_ex`
- `ASN1_item_unpack`
- `ASN1_item_unpack_ex`
- `ASN1_item_verify`
- `ASN1_item_verify_ctx`
- `ASN1_item_verify_ex`

### Completed - Batch 100
- `ASN1_add_oid_module`
- `ASN1_add_stable_module`
- `ASN1_bn_print`
- `ASN1_buf_print`
- `ASN1_check_infinite_end`
- `ASN1_const_check_infinite_end`
- `ASN1_d2i_fp`
- `ASN1_digest`
- `ASN1_dup`
- `ASN1_generate_nconf`
- `ASN1_generate_v3`
- `ASN1_get_object`
- `ASN1_i2d_fp`
- `ASN1_mbstring_copy`
- `ASN1_mbstring_ncopy`
- `ASN1_object_size`
- `ASN1_parse`
- `ASN1_parse_dump`
- `ASN1_put_eoc`
- `ASN1_put_object`
- `ASN1_sign`
- `ASN1_str2mask`
- `ASN1_tag2bit`
- `ASN1_tag2str`
- `ASN1_verify`

### Completed - Batch 101
- `ACCESS_DESCRIPTION_free`
- `ACCESS_DESCRIPTION_it`
- `ACCESS_DESCRIPTION_new`

### Completed - Batch 102
- `ADMISSION_SYNTAX_free`
- `ADMISSION_SYNTAX_get0_admissionAuthority`
- `ADMISSION_SYNTAX_get0_contentsOfAdmissions`
- `ADMISSION_SYNTAX_it`
- `ADMISSION_SYNTAX_new`
- `ADMISSION_SYNTAX_set0_admissionAuthority`
- `ADMISSION_SYNTAX_set0_contentsOfAdmissions`

### Completed - Batch 103
- `ADMISSIONS_free`
- `ADMISSIONS_get0_admissionAuthority`
- `ADMISSIONS_get0_namingAuthority`
- `ADMISSIONS_get0_professionInfos`
- `ADMISSIONS_it`
- `ADMISSIONS_new`
- `ADMISSIONS_set0_admissionAuthority`
- `ADMISSIONS_set0_namingAuthority`
- `ADMISSIONS_set0_professionInfos`

### Completed - Batch 104
- `AUTHORITY_INFO_ACCESS_free`
- `AUTHORITY_INFO_ACCESS_it`
- `AUTHORITY_INFO_ACCESS_new`

### Completed - Batch 105
- `AUTHORITY_KEYID_free`
- `AUTHORITY_KEYID_it`
- `AUTHORITY_KEYID_new`

### Completed - Batch 106
- `BASIC_CONSTRAINTS_free`
- `BASIC_CONSTRAINTS_it`
- `BASIC_CONSTRAINTS_new`

### Completed - Batch 107
- `DIST_POINT_NAME_dup`
- `DIST_POINT_NAME_free`
- `DIST_POINT_NAME_it`
- `DIST_POINT_NAME_new`
- `DIST_POINT_free`
- `DIST_POINT_it`
- `DIST_POINT_new`
- `DIST_POINT_set_dpname`


### Completed - Batch 108
- `CRL_DIST_POINTS_free`
- `CRL_DIST_POINTS_it`
- `CRL_DIST_POINTS_new`

### Completed - Batch 109
- `DIST_POINT_NAME_dup`
- `DIST_POINT_NAME_free`
- `DIST_POINT_NAME_it`
- `DIST_POINT_NAME_new`
- `DIST_POINT_free`
- `DIST_POINT_it`
- `DIST_POINT_new`
- `DIST_POINT_set_dpname`

### Completed - Batch 110
- `GENERAL_NAMES_free`
- `GENERAL_NAMES_it`
- `GENERAL_NAMES_new`

### Completed - Batch 111
- `GENERAL_NAME_cmp`
- `GENERAL_NAME_dup`
- `GENERAL_NAME_free`
- `GENERAL_NAME_get0_otherName`
- `GENERAL_NAME_get0_value`
- `GENERAL_NAME_it`
- `GENERAL_NAME_new`
- `GENERAL_NAME_print`
- `GENERAL_NAME_set0_othername`
- `GENERAL_NAME_set0_value`
- `GENERAL_NAME_set1_X509_NAME`

### Completed - Batch 112
- `GENERAL_SUBTREE_free`
- `GENERAL_SUBTREE_it`
- `GENERAL_SUBTREE_new`

### Completed - Batch 113
- `ISSUING_DIST_POINT_free`
- `ISSUING_DIST_POINT_it`
- `ISSUING_DIST_POINT_new`

### Completed - Batch 114
- `NAME_CONSTRAINTS_check`
- `NAME_CONSTRAINTS_check_CN`
- `NAME_CONSTRAINTS_free`
- `NAME_CONSTRAINTS_it`
- `NAME_CONSTRAINTS_new`

### Completed - Batch 115
- `ASIdOrRange_free`
- `ASIdOrRange_it`
- `ASIdOrRange_new`

### Completed - Batch 116
- `ASIdentifierChoice_free`
- `ASIdentifierChoice_it`
- `ASIdentifierChoice_new`

### Completed - Batch 117
- `ASIdentifiers_free`
- `ASIdentifiers_it`
- `ASIdentifiers_new`

### Completed - Batch 118
- `ASRange_free`
- `ASRange_it`
- `ASRange_new`

### Batch 002 - X509 / PEM / Store / OCSP family

Why first:
- Highest remaining verified call volume after batch 001.
- Current state mixes `partial`, `not_available`, and `missing`.
- This batch affects certificate verification, parsing, and trust-store heavy projects.

Representative interfaces:
- `X509_new`
- `X509_free`
- `X509_dup`
- `X509_get_subject_name`
- `X509_get_issuer_name`
- `X509_get_ext_d2i`
- `X509_verify_cert`
- `X509_STORE_add_cert`
- `X509_STORE_free`
- `X509_STORE_CTX_get_error`
- `PEM_read_bio_X509`
- `X509_REQ_new`
- `X509_REQ_free`
- `OCSP_BASICRESP_free`
- `OCSP_RESPONSE_free`
- `sk_X509_num`
- `sk_X509_value`
- `sk_X509_pop_free`
- `sk_X509_push`

Primary dimensions:
- object ownership / refcount
- parser/decoder equivalence
- store / verification lifecycle
- extension accessor model
- container/list replacement strategy

### Batch 003 - EVP_PKEY / RSA / EC / DH family

Why second:
- High call volume and broad impact across crypto-heavy projects.
- Several current mappings are directionally plausible but need stronger source evidence.
- Ownership semantics and context lifecycle matter heavily here.

Representative interfaces:
- `EVP_PKEY_new`
- `EVP_PKEY_free`
- `EVP_PKEY_CTX_new`
- `EVP_PKEY_CTX_free`
- `RSA_new`
- `RSA_free`
- `DH_free`
- `EC_KEY_free`
- `EC_POINT_new`
- `EC_GROUP_free`
- `EC_KEY_get0_group`

Primary dimensions:
- key/context lifecycle
- algorithm-specific vs generic key model
- whether replacement is direct public API or composed public API
- ownership and duplication semantics

### Batch 004 - ERR / OPENSSL util / OBJ family

Why third:
- High call volume and several `missing` entries.
- These interfaces are small individually but heavily used in control flow and diagnostics.
- Current coverage interpretation is noisy until these entries are cleaned up.

Representative interfaces:
- `ERR_get_error`
- `ERR_error_string`
- `ERR_clear_error`
- `ERR_reason_error_string`
- `ERR_GET_REASON`
- `OPENSSL_free`
- `OBJ_obj2txt`

Primary dimensions:
- error-stack behavior
- stringification / formatting helpers
- macro vs function distinction
- memory utility semantics

### Batch 005 - BN / low-level numeric family

Why fourth:
- Very high call volume.
- Most entries are currently `not_available` or `missing`.
- This batch is likely to confirm a large number of true public-API gaps quickly.

Representative interfaces:
- `BN_new`
- `BN_free`
- `BN_clear_free`
- `BN_bin2bn`
- `BN_bn2bin`
- `BN_num_bytes`
- `BN_set_word`
- `BN_CTX_new`
- `BN_CTX_free`

Primary dimensions:
- whether public big-number APIs exist at all
- whether migration must happen through higher-level key/cert APIs
- whether any "not_available" entries should remain that way

### Batch 006 - BIO / UIO extended family

Why fifth:
- Batch 001 only covered the two most common BIO cases.
- Remaining BIO entries need consistent rules around direct vs composed replacement.

Representative interfaces:
- `BIO_new`
- `BIO_new_mem_buf`
- `BIO_s_mem`
- `BIO_read`
- `BIO_printf`
- `BIO_free_all`

Primary dimensions:
- constructor pattern differences
- memory/file/socket UIO method composition
- return model differences
- whether formatted output helpers have public equivalents

### Batch 007 - SSL core lifecycle / context helpers

Why sixth:
- Call volume is meaningful, but semantic surface is narrower than the batches above.
- Many entries are already clearly `partial`; the work is mainly to make the rationale rigorous.

Representative interfaces:
- `SSL_new`
- `SSL_free`
- `SSL_get_error`
- `SSL_CTX_free`
- `SSL_CTX_get_cert_store`
- `TLS_client_method`
- `SSL_set_options`

Primary dimensions:
- config vs connection split
- state machine / endpoint setup
- error model and option model
- trust-store access semantics

### Batch 008 - Cipher / digest helper family

Why seventh:
- Moderate call volume.
- Mostly already directionally mapped, but still needs full evidence chains for truth-library quality.

Representative interfaces:
- `EVP_CIPHER_CTX_new`
- `EVP_CIPHER_CTX_free`
- `EVP_CIPHER_CTX_ctrl`
- `EVP_CIPHER_CTX_set_padding`
- `EVP_EncryptInit_ex`
- `EVP_DecryptInit_ex`
- `EVP_MD_CTX_new`
- `EVP_MD_CTX_free`
- `EVP_sha256`
- `EVP_sha384`
- `EVP_sha512`

Primary dimensions:
- context creation model
- algorithm binding point
- ctrl/padding/state constraints
- helper-constant vs API replacement semantics

### Deferred / low-priority batch - ASN1 macro-like symbols

Why deferred:
- Call volume exists, but many of these are macros or internal construction helpers rather than meaningful public substitution targets.
- Need a rule first: which macro-like OpenSSL symbols should remain in truth library versus be excluded from compatibility reporting.

Representative interfaces:
- `ASN1_SIMPLE`
- `ASN1_EXP_OPT`
- `ASN1_SEQUENCE_END`
- `ASN1_STRING_length`
- `ASN1_STRING_get0_data`

## Per-interface verification workflow

For every interface:
1. Confirm OpenSSL public declaration.
2. Confirm openHiTLS public declaration.
3. Trace openHiTLS implementation entry and at least one deeper call-flow hop.
4. Decide:
   - `available`
   - `partial`
   - `not_available`
5. Record:
   - replacement kind
   - concise rationale
   - evidence paths
6. Update batch document first.
7. Update `hitls_compat.json` only after document text is stable.

## Success criteria for each batch

- Every updated entry has:
  - `status`
  - `hitls`
  - `notes`
  - `replacement_kind`
  - `analysis_doc`
  - `evidence`
- Every verdict is traceable to public declarations plus implementation evidence.
- No `available` entry is left without strong justification.
- `missing` entries in the batch are eliminated or explicitly deferred with rationale.
