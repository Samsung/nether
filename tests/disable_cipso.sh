#!/bin/bash

echo 127.0.0.1 -CIPSO > /sys/fs/smackfs/netlabel
echo 0.0.0.0/0 @ > /sys/fs/smackfs/netlabel