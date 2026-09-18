# Security policy

Report vulnerabilities privately — open a
[security advisory](https://github.com/MartinRougeron2/HQChat-Server/security/advisories/new)
rather than a public issue.

This server's whole claim is that it cannot read messages. Anything undermining
that is the most serious class of bug we have: recovering plaintext or key
material from what the server holds; publishing to or subscribing to a
conversation you are not a member of (the per-topic ACL is the only barrier, and
topic names are derivable from two public keys); authenticating as another public
key; or replaying a handshake or token.

Open findings are tracked privately, in the monorepo this code is published
from: a list of unfixed weaknesses beside the code that has them helps the wrong
reader first. If you report something already on it we will say so, and say when
it is expected to close.

Full policy, including scope: [SECURITY.md](../../SECURITY.md).
