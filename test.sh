#!/bin/bash

i=0
echo "\t Name \t Time \t Memory_Used \t CPU_Used" >> ./results
while [ $i -le 5 ]
do
find /usr/src/ -type f > to_touch

FILENAME=to_touch

touched=0
while read line
do
rnd=$((RANDOM % 100))
if [ $rnd -lt 50 ]
then
    touched=$touched+1
    touch $line
    echo $line >> ./touched_data
fi

done < $FILENAME

echo $touched >> ./results

time -f "\t%C\t%E\t%K\t%P" ./rsync-test / /srv/scratch/ka50xebo/backup_fanotify >> ./results

time -f "\t%C\t%E\t%K\t%P" rsync -brp /usr/src /srv/scratch/ka50xebo/backup_normal >> ./results

diff /var/lib/watcher/output ./touched_data | wc >> ./results

rm ./to_touch
rm ./touched_data

i=$i+1
done