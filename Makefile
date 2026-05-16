.DEFAULT_GOAL = run

# Runs all services in detached mode.
.PHONY: run
run:
	docker compose --env-file .env.local up -d --build

# Runs all services without detached mode (for debugging).
.PHONY: rund
rund:
	docker compose --env-file .env.local up --build

# Shows all service statuses.
.PHONY: services
services:
	docker compose --env-file .env.local ps

# Shows logs.
.PHONY: logs
logs:
	docker compose --env-file .env.local logs -f

# App logs only.
.PHONY: logs-app
logs-app:
	docker compose --env-file .env.local logs -f app

# Stops all running services.
.PHONY: stop
stop:
	docker compose --env-file .env.local down

# Cleans up all resources including volumes.
.PHONY: clean
clean:
	docker compose --env-file .env.local down -v

# Full rebuild from scratch.
.PHONY: rebuild
rebuild:
	docker compose --env-file .env.local down -v
	docker compose --env-file .env.local up -d --build

# Opens shell inside app container.
.PHONY: shell
shell:
	docker compose --env-file .env.local exec app sh

# Healthcheck.
.PHONY: health
health:
	curl -i http://localhost:8080/health

# Redis CLI.
.PHONY: redis
redis:
	docker compose --env-file .env.local exec redis redis-cli -n $$(grep REDIS_DB .env.local | cut -d '=' -f2)

# Cassandra CQL shell.
.PHONY: cql
cql:
	docker compose --env-file .env.local exec cassandra cqlsh

# Mongo shell.
.PHONY: mongo
mongo:
	docker compose --env-file .env.local exec mongos mongosh

# Check reviews cache in Redis.
.PHONY: redis-reviews
redis-reviews:
	docker compose --env-file .env.local exec redis redis-cli -n $$(grep REDIS_DB .env.local | cut -d '=' -f2) KEYS "event:*:reviews"

# Check Cassandra review rows.
.PHONY: cassandra-reviews
cassandra-reviews:
	docker compose --env-file .env.local exec cassandra cqlsh -e "SELECT * FROM $$(grep CASSANDRA_KEYSPACE .env.local | cut -d '=' -f2).event_reviews;"