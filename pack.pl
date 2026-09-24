name(hornguard).
version('0.1.1').
title('Default-deny firewall for untrusted Prolog goals and clauses').
author('DataGrout', 'https://github.com/DataGrout').
home('https://github.com/DataGrout/hornguard').
% GitHub serves an archive for every tag, so a tag is enough for
% pack_install/1 to find a version; the release workflow adds the notes.
download('https://github.com/DataGrout/hornguard/archive/v*.zip').
requires(prolog >= '9.2').
