DOCKERFILE=docker-compose.yml
docker-compose -f $DOCKERFILE down ;rm -rf  /tmp/keyValStore*; rm -rf  /tmp/kvs-hfc-e2e ~/test.properties; rm -rf /var/hyperledger/*  ; docker-compose -f $DOCKERFILE up --force-recreate
#docker-compose -f $DOCKERFILE down ;rm -rf  /tmp/keyValStore*; rm -rf  /tmp/kvs-hfc-e2e ; rm -rf /var/hyperledger/*  ; docker-compose -f $DOCKERFILE up --force-recreate
