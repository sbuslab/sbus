SHELL:=/bin/bash
VERSION ?= $(shell git describe --tags --abbrev=0 | sed 's/v//')

bump-tag:
	TAG=$$(echo "v${VERSION}" | awk -F. '{$$NF = $$NF + 1;} 1' | sed 's/ /./g'); \
	git tag $$TAG; \
	git push && git push --tags

release:
	gradle clean publish -Pversion="${VERSION}" --info --refresh-dependencies
