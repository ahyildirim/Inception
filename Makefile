NAME = docker_app

DOCKER_COMPOSE = docker compose -f ./srcs/docker-compose.yml


all:
	@$(DOCKER_COMPOSE) build --no-cache
	@$(DOCKER_COMPOSE) up -d --build

up:
	@$(DOCKER_COMPOSE) up

down:
	@$(DOCKER_COMPOSE) down

clean:
	@$(DOCKER_COMPOSE) down -v --remove-orphans

re: clean all
