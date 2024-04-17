#/bin/bash
set -e

N=10
MAX_CONNECTIONS=10
TYPES=('none' 'secure' 'uni' 'bid')

for t in "${TYPES[@]}"
do
    echo "Performing tests for type '$t'"
    for i in $(seq $MAX_CONNECTIONS)
    do
        ./DDSPerformanceTestWithTPMExample $t $i $N
        echo ''
    done
done
