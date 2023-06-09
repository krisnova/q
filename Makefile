# Copyright © 2023 Kris Nóva <nova@nivenly.org>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

CC       = clang

default: compile servers ## Default to compile

.PHONY: clean
clean: ## Clean objects
	cd ebpf && make clean
	cd servers && make clean
	rm -vrf target/*
	rm -vf *.o
	rm -vf *.ll

.PHONY: ebpf
ebpf: ## Compile eBPF probe code
	cd ebpf && make compile

compile: ebpf ## Compile local rust code
	cargo build --target=x86_64-unknown-linux-musl

install: ## Install into $PATH
	cargo install --path q --target=x86_64-unknown-linux-musl

servers: ## Compile "servers" code
	cd servers && make compile

.PHONY: help
help:  ## Show help messages for make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(firstword $(MAKEFILE_LIST)) | sort | awk 'BEGIN {FS = ":.*?## "}; {//printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}'
