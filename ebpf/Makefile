# Copyright © 2022 Kris Nóva <nova@nivenly.org>
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

default: compile ## Default to compile

.PHONY: clean
clean: ## Clean objects
	rm -rvf target/*

compile: ## Compile local eBPF code
	cargo +nightly build --release --target=bpfel-unknown-none -Z build-std=core

.PHONY: bindings
bindings: ## Use aya-tool to build kernel header bindings
	@#TODO add a check for 'aya-tool' and 'bindgen'
	cargo install bindgen-cli
	cargo install --git https://github.com/aya-rs/aya -- aya-tool
	aya-tool generate task_struct > src/binding.rs

.PHONY: help
help:  ## Show help messages for make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(firstword $(MAKEFILE_LIST)) | sort | awk 'BEGIN {FS = ":.*?## "}; {//printf "\033[32m%-30s\033[0m %s\n", $$1, $$2}'
