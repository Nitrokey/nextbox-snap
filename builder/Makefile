CONT_NAME=build-nextbox-snap
BINDDIR=$(abspath $(shell pwd)/..)

build: run-container
	docker exec -it $(CONT_NAME) apt-get install -y snapcraft
	docker exec -it $(CONT_NAME) snapcraft

bash: run-container
	docker exec -it $(CONT_NAME) /bin/bash

run-container: image
	[[ -r run-container ]] && make stop || true
	docker run -ti \
		--name $(CONT_NAME) \
		--mount type=bind,source=$(BINDDIR),target=/bind \
		--cap-add SYS_ADMIN \
    --device=/dev/fuse \
    --security-opt apparmor:unconfined \
    --security-opt seccomp:unconfined \
    -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
    -v /lib/modules:/lib/modules:ro \
		-d \
		$(CONT_NAME)
	
	# wait a little as this container really "boots" ...
	sleep 10

	touch $@

stop:
	@-docker stop $(CONT_NAME)
	@-docker rm $(CONT_NAME)
	rm -f run-container

clean: stop
	rm -f image


image: Dockerfile
	docker build -t $(CONT_NAME) --force-rm=true --rm=true .
	touch $@


#.PHONY: stop
