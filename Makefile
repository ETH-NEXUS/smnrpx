build:
	@docker build --no-cache . -t ethnexus/smnrpx
docker: build
	@docker push ethnexus/smnrpx