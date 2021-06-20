version = "0.0.1"
change-version:
	@echo $(VERSION)>VERSION

update:
	go get -v golang.org/x/crypto

run:
	go run bin/main.go

push:
	git push origin master