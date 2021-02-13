CONT_NAME=test-snap
BINDDIR=$(shell pwd)

startup: clean
	
	docker run -ti \
		--name $(CONT_NAME) \
		--mount type=bind,source=$(BINDDIR),target=/bind \
		--cap-add SYS_ADMIN \
    --device=/dev/fuse \
    --security-opt apparmor:unconfined \
    --security-opt seccomp:unconfined \
    -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
    -v /lib/modules:/lib/modules:ro \
		$(CONT_NAME)-image

	# wait a little as this container really "boots" ...
	sleep 10

clean:
	@-docker stop $(CONT_NAME)
	@-docker rm $(CONT_NAME)

image:
	docker build -t $(CONT_NAME)-image --force-rm=true --rm=true .


