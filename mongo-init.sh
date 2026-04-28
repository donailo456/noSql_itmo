#!/bin/bash

echo "=== Waiting for MongoDB instances to start ==="
sleep 10

echo "=== Initializing Config Server Replica Set ==="
for i in {1..30}; do
  RESULT=$(mongosh --host cfgsvr1 --port 27019 --quiet --eval "
    rs.initiate({
      _id: 'cfgReplSet',
      configsvr: true,
      members: [{ _id: 0, host: 'cfgsvr1:27019' }]
    })
  " 2>&1) || true
  if echo "$RESULT" | grep -qE "ok.*1|already"; then
    echo "Config server replica set initiated"
    break
  fi
  echo "Waiting for config server... attempt $i"
  sleep 3
done

sleep 5

echo "=== Initializing Shard 1 Replica Set ==="
for i in {1..30}; do
  RESULT=$(mongosh --host shard1svr1 --port 27020 --quiet --eval "
    rs.initiate({
      _id: 'shard1ReplSet',
      members: [
        { _id: 0, host: 'shard1svr1:27020', priority: 2 },
        { _id: 1, host: 'shard1svr2:27021', priority: 1 },
        { _id: 2, host: 'shard1svr3:27022', priority: 1 }
      ]
    })
  " 2>&1) || true
  if echo "$RESULT" | grep -qE "ok.*1|already"; then
    echo "Shard 1 replica set initiated"
    break
  fi
  echo "Waiting for shard 1... attempt $i"
  sleep 3
done

sleep 5

echo "=== Initializing Shard 2 Replica Set ==="
for i in {1..30}; do
  RESULT=$(mongosh --host shard2svr1 --port 27023 --quiet --eval "
    rs.initiate({
      _id: 'shard2ReplSet',
      members: [
        { _id: 0, host: 'shard2svr1:27023', priority: 2 },
        { _id: 1, host: 'shard2svr2:27024', priority: 1 },
        { _id: 2, host: 'shard2svr3:27025', priority: 1 }
      ]
    })
  " 2>&1) || true
  if echo "$RESULT" | grep -qE "ok.*1|already"; then
    echo "Shard 2 replica set initiated"
    break
  fi
  echo "Waiting for shard 2... attempt $i"
  sleep 3
done

sleep 10

echo "=== Waiting for Shard 1 PRIMARY ==="
for i in {1..60}; do
  RESULT=$(mongosh --host shard1svr1 --port 27020 --quiet --eval "
    try {
      const status = rs.status();
      const primary = status.members.find(m => m.stateStr === 'PRIMARY');
      print(primary ? 'true' : 'false');
    } catch (e) {
      print('false');
    }
  " 2>/dev/null || true)

  if echo "$RESULT" | grep -q "true"; then
    echo "Shard 1 PRIMARY is ready"
    break
  fi

  echo "Waiting for shard 1 PRIMARY... attempt $i"
  sleep 2
done

echo "=== Waiting for Shard 2 PRIMARY ==="
for i in {1..60}; do
  RESULT=$(mongosh --host shard2svr1 --port 27023 --quiet --eval "
    try {
      const status = rs.status();
      const primary = status.members.find(m => m.stateStr === 'PRIMARY');
      print(primary ? 'true' : 'false');
    } catch (e) {
      print('false');
    }
  " 2>/dev/null || true)

  if echo "$RESULT" | grep -q "true"; then
    echo "Shard 2 PRIMARY is ready"
    break
  fi

  echo "Waiting for shard 2 PRIMARY... attempt $i"
  sleep 2
done

echo "=== Adding Shards via Mongos ==="

for i in {1..30}; do
  RESULT=$(mongosh --host mongos --port 27017 --quiet --eval "
    sh.addShard('shard1ReplSet/shard1svr1:27020,shard1svr2:27021,shard1svr3:27022')
  " 2>&1) || true
  if echo "$RESULT" | grep -qE "ok.*1|already|shardAlreadyExists"; then
    echo "Shard 1 added"
    break
  fi
  echo "Waiting to add shard 1... attempt $i"
  sleep 5
done

sleep 3

for i in {1..30}; do
  RESULT=$(mongosh --host mongos --port 27017 --quiet --eval "
    sh.addShard('shard2ReplSet/shard2svr1:27023,shard2svr2:27024,shard2svr3:27025')
  " 2>&1) || true
  if echo "$RESULT" | grep -qE "ok.*1|already|shardAlreadyExists"; then
    echo "Shard 2 added"
    break
  fi
  echo "Waiting to add shard 2... attempt $i"
  sleep 5
done

sleep 3

echo "=== Enabling Sharding ==="

mongosh --host mongos --port 27017 --quiet --eval "
  sh.enableSharding('eventhub');
" 2>&1 || echo "Sharding may already be enabled"

sleep 2

echo "=== Sharding events collection ==="
mongosh --host mongos --port 27017 --quiet --eval "
  db = db.getSiblingDB('eventhub');
  db.events.createIndex({ created_by: 'hashed' });
  sh.shardCollection('eventhub.events', { created_by: 'hashed' });
" 2>&1 || echo "events collection may already be sharded"

echo "=== Sharding initialization complete ==="
