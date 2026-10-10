import re, sys
p = sys.argv[1]
s = open(p).read()
m = re.search(r"fn init\([^)]*\)[^{]*\{", s)
s = s[:m.end()] + "\n        let _ = core::hint::black_box(&PAD[..]);" + s[m.end():]
open(p, "w").write(s)
