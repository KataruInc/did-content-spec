# did:content specification repository (public). Server/infra live in did-content-backend.
.PHONY: test examples check-examples

test: ## Python reference implementation tests
	cd app && python3 -m unittest discover -s tests

examples: ## Regenerate test vectors (deterministic)
	cd app && python3 make_examples.py

check-examples: examples ## Fail if examples/ is stale
	git diff --exit-code -- examples/
