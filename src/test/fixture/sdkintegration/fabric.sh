#!/usr/bin/env bash
# simple batch script making it easier to cleanup and start a relatively fresh fabric env.

if [ ! -e "docker-compose.yaml" ];then
  echo "docker-compose.yaml not found."
  exit 8
fi


function clean(){

  rm -rf /var/hyperledger/*

  if [ -e "/tmp/HFCSampletest.properties" ];then
    rm -f "/tmp/HFCSampletest.properties"
  fi

  lines=`docker ps -a | grep 'dev-peer' | wc -l`

  if [ "$lines" -gt 0 ]; then
    docker ps -a | grep 'dev-peer' | awk '{print $1}' | xargs docker rm -f
  fi

  lines=`docker images | grep 'dev-peer' | grep 'dev-peer' | wc -l`
  if [ "$lines" -gt 0 ]; then
    docker images | grep 'dev-peer' | awk '{print $1}' | xargs docker rmi -f
  fi

}

function up(){
  docker-compose up --force-recreate
}

function down(){
  docker-compose down;
}


for opt in "$@"
do

    case "$opt" in
        up)
            up
            ;;
        down)
            down
            ;;
        clean)
            clean
            ;;
        restart)
            down
            clean
            up
            ;;

        *)
            echo $"Usage: $0 {up|down|clean|restart}"
            exit 1

esac
done