for dir in $1/*
do
    python utils/submit.py $dir --enforce-timeout
done
