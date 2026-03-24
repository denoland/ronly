LIMA_CARGO = export CARGO_TARGET_DIR=/tmp/ronly-target && \
	cd /Users/ry/src/ronly

build-lima:
	limactl shell default bash -c \
	  '$(LIMA_CARGO) && \
	   $$HOME/.cargo/bin/cargo build --release 2>&1'

REMOTE_HOST ?= wind-satyr.exe.xyz
REMOTE_DIR = /tmp/ronly-src

# Lima doesn't support unprivileged user namespaces,
# so local tests run privileged. Rootless tested via
# test-rootless (remote VM) and CI.
test: test-privileged test-rootless

test-privileged:
	limactl shell default bash -c \
	  '$(LIMA_CARGO) && \
	   sudo -E env "PATH=$$PATH" \
	     RONLY_TEST_MODE=privileged \
	     $$HOME/.cargo/bin/cargo test --release 2>&1'

test-rootless:
	rsync -a --exclude target --exclude .git \
	  . $(REMOTE_HOST):$(REMOTE_DIR)/
	ssh $(REMOTE_HOST) \
	  'cd $(REMOTE_DIR) && \
	   $$HOME/.cargo/bin/cargo test --release 2>&1'
