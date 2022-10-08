#!/bin/bash
tar -cf pkg.tar $(find -maxdepth 1 | grep -vE "\.$|.git|.zst|.tar|.sh" | cut -c3-) && zstd --compress -f pkg.tar && rm pkg.tar
