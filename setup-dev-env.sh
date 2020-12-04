#/bin/bash

if [[ $(docker images | grep pcappp) != 0 ]]; then
  docker build -t pcappp .
fi

docker run --rm -it -v $PWD:$PWD -w $PWD pcappp bash
